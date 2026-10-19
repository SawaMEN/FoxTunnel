//go:build neqo && cgo && linux && amd64

package neqo

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A bounded userspace UDP link drops actual QUIC datagrams, unlike a lost HTTP
// ACK model. Delay is applied independently in both directions. It is not a
// calibrated bandwidth emulator or a field route.
func lossyUDP(t *testing.T, upstream string, delay time.Duration, every int) (string, *atomic.Int64) {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	back, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		front.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var mu sync.Mutex
	var client *net.UDPAddr
	var dropped atomic.Int64
	type packet struct {
		data []byte
		at   time.Time
		peer *net.UDPAddr
	}
	up, down := make(chan packet, 64), make(chan packet, 64)
	reader := func(socket *net.UDPConn, queue chan<- packet, fromClient bool) {
		defer wg.Done()
		buffer := make([]byte, 65535)
		count := 0
		for {
			n, peer, err := socket.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			count++
			mu.Lock()
			if fromClient {
				client = peer
			} else {
				peer = client
			}
			mu.Unlock()
			if peer == nil {
				continue
			}
			if every > 0 && count%every == 0 {
				dropped.Add(1)
				continue
			}
			p := packet{data: append([]byte(nil), buffer[:n]...), at: time.Now().Add(delay), peer: peer}
			select {
			case queue <- p:
			case <-ctx.Done():
				return
			}
		}
	}
	writer := func(queue <-chan packet, toClient bool) {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-queue:
				timer := time.NewTimer(max(0, time.Until(p.at)))
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return
				}
				var writeErr error
				if toClient {
					_, writeErr = front.WriteToUDP(p.data, p.peer)
				} else {
					_, writeErr = back.Write(p.data)
				}
				if writeErr != nil {
					return
				}
			}
		}
	}
	wg.Add(4)
	go reader(front, up, true)
	go reader(back, down, false)
	go writer(up, false)
	go writer(down, true)
	t.Cleanup(func() { cancel(); front.Close(); back.Close(); wg.Wait() })
	return front.LocalAddr().String(), &dropped
}
func TestRealQUICDatagramLossAndDelay(t *testing.T) {
	raw, cfg := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		_, _ = io.Copy(flushing{w}, r.Body)
	}))
	server, _ := url.Parse(raw)
	proxy, dropped := lossyUDP(t, server.Host, 5*time.Millisecond, 17)
	client, err := NewTransport(Config{TLS: cfg, HandshakeTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	payload := make([]byte, 256<<10)
	for i := range payload {
		payload[i] = byte((i*7 + i/32768) % 251)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://"+proxy+"/echo", bytes.NewReader(payload))
	started := time.Now()
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("QUIC packet loss corrupted the stream", len(got), err)
	}
	if dropped.Load() == 0 {
		t.Fatal("loss scenario did not drop datagrams")
	}
	t.Logf("256 KiB echo, 5ms per direction, drop each 17th datagram: %v; dropped=%d", time.Since(started), dropped.Load())
}
