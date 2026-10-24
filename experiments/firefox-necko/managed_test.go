package firefox

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/SawaMEN/FoxTunnel/internal/udpproto"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestGeckoManagedIPC(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified integration bundle required")
	}
	var requests, nativePOST, nativeH2, nativeAuth atomic.Int32
	server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true, EnableUDP: true}
	cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/.well-known/foxtunnel-udp-v1" {
			nativePOST.Add(1)
			if r.ProtoMajor == 2 {
				nativeH2.Add(1)
			}
			if r.Header.Get("Proxy-Authorization") != "" {
				nativeAuth.Add(1)
			}
		}
		server.ServeHTTP(w, r)
	}))
	m, err := NewManaged(bundle, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = m.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	listen, tag := m.listen, m.profileTag
	m.mu.Unlock()
	if tag == "" || filepath.Base(tag) != tag {
		t.Fatal("invalid private profile tag")
	}
	for _, method := range []byte{0, 2} {
		c, e := net.DialTimeout("tcp", listen, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write([]byte{5, 1, method})
		var reply [2]byte
		if _, e = io.ReadFull(c, reply[:]); e != nil {
			c.Close()
			// Rejection may close the socket before the queued failure
			// frame reaches TCP. EOF is denial; timeout or success is not.
			if method == 0 && (errors.Is(e, io.EOF) || errors.Is(e, io.ErrUnexpectedEOF)) {
				continue
			}
			t.Fatal(e)
		}
		if method == 0 {
			if reply != [2]byte{5, 255} {
				t.Fatal("IPC accepted unauthenticated SOCKS")
			}
		} else {
			if reply != [2]byte{5, 2} {
				t.Fatal("IPC password method not selected")
			}
			c.Write([]byte{1, 1, 'x', 1, 'x'})
			_, e = io.ReadFull(c, reply[:])
			if e != nil {
				if !errors.Is(e, io.EOF) && !errors.Is(e, io.ErrUnexpectedEOF) {
					t.Fatal("IPC rejection did not finish", e)
				}
			} else if reply != [2]byte{1, 1} {
				t.Fatal("IPC accepted incorrect credentials")
			}
		}
		c.Close()
	}
	if requests.Load() != 0 {
		t.Fatal("unauthenticated IPC reached the HTTPS proxy")
	}
	c, err := m.DialContext(ctx, "tcp", nativeEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("binary\x00\xff"))
	c.(interface{ CloseWrite() error }).CloseWrite()
	got, err := io.ReadAll(c)
	c.Close()
	if err != nil || string(got) != "binary\x00\xff" {
		t.Fatal("authenticated IPC transfer failed", err)
	}
	// Exercise the real native Necko HTTP POST path, not an in-process
	// Go RoundTripper. An authenticated loopback IPC command must reach
	// the existing UDP-v1 endpoint over verified Mozilla HTTP/2.
	datagramTarget, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer datagramTarget.Close()
	go func() {
		var buf [2048]byte
		for {
			n, peer, err := datagramTarget.ReadFrom(buf[:])
			if err != nil {
				return
			}
			_, _ = datagramTarget.WriteTo(buf[:n], peer)
		}
	}()
	payload := []byte{0, 1, 2, 0xff, 0, 0x80, 0x42}
	wire, e := udpproto.Encode(udpproto.Packet{
		Host: "127.0.0.1", Port: uint16(datagramTarget.LocalAddr().(*net.UDPAddr).Port), Data: payload,
	})
	if e != nil {
		t.Fatal(e)
	}
	dgctx, stopUDP := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopUDP()
	result, e := m.ExchangeUDP(dgctx, wire)
	if e != nil {
		t.Fatalf("native Gecko UDP v1 relay: %v; UDP HTTP observed=%d H2=%d proxy-auth-present=%d", e, nativePOST.Load(), nativeH2.Load(), nativeAuth.Load())
	}
	response, e := udpproto.Parse(result)
	if e != nil || string(response.Data) != string(payload) || response.Port != uint16(datagramTarget.LocalAddr().(*net.UDPAddr).Port) {
		t.Fatalf("native UDP reply invalid: %v", e)
	}
	if requests.Load() < 2 {
		t.Fatal("native UDP POST did not reach the HTTPS proxy")
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(os.TempDir(), tag)); !os.IsNotExist(err) {
		t.Fatal("private helper profile survived Close")
	}
	if c, err = net.DialTimeout("tcp", listen, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("helper listener survived Close")
	}
}

// The peer flushes response headers before reading upload bytes. This detects
// Gecko buffering an unknown-length upload until EOF, as well as lost duplex.
func TestGeckoManagedUDPStream(t *testing.T) {
	bundle := os.Getenv("FOXTUNNEL_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified integration bundle required")
	}
	var posts atomic.Int32
	cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/foxtunnel-udp-stream-v2" || r.Method != "POST" || r.ProtoMajor != 2 || r.Header.Get("Proxy-Authorization") == "" {
			http.Error(w, "invalid stream", http.StatusBadRequest)
			return
		}
		posts.Add(1)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			packet, err := udpproto.ReadFrame(r.Body)
			if err != nil {
				return
			}
			if err := udpproto.WriteFrame(w, packet); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	m, err := NewManaged(bundle, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	stream, err := m.OpenUDPStream(ctx)
	if err != nil {
		t.Fatal("native response-before-upload handshake:", err)
	}
	defer stream.Close()
	// Transfer several MiB through the two 64-KiB native pipes. Upload and
	// download run independently: a request/reply loop cannot expose a deadlock
	// caused by blocked response delivery while Gecko is still uploading.
	const frames = 4096
	packet := func(sequence int) []byte {
		data := make([]byte, udpproto.MaxDatagram-10)
		for i := range data {
			data[i] = byte(i + sequence)
		}
		binary.BigEndian.PutUint32(data, uint32(sequence))
		wire, err := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: 53, Data: data})
		if err != nil {
			panic(err)
		}
		return wire
	}
	sent := make(chan error, 1)
	go func() {
		for i := 0; i < frames; i++ {
			if err := udpproto.WriteFrame(stream, packet(i)); err != nil {
				sent <- err
				return
			}
		}
		sent <- nil
	}()
	// Let the echo fill the download pipe before starting the reader.
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < frames; i++ {
		got, err := udpproto.ReadFrame(stream)
		if err != nil || !bytes.Equal(got, packet(i)) {
			t.Fatalf("native duplex frame %d: %v", i, err)
		}
	}
	if err := <-sent; err != nil {
		t.Fatal("native upload:", err)
	}
	if posts.Load() != 1 {
		t.Fatal("stream reopened the HTTP request")
	}
	cancel()
	if _, err := stream.Read(make([]byte, 1)); err == nil {
		t.Fatal("cancel did not close flow")
	}
}
