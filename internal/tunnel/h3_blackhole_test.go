package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// udpGate drops both directions of established client paths while continuing
// to pass new UDP clients. This models a stale QUIC path without a clean close
// frame and runs identically on Linux, macOS and Windows.
type udpGate struct {
	front   *net.UDPConn
	backend *net.UDPAddr
	mu      sync.Mutex
	peers   map[string]*net.UDPConn
	blocked map[string]bool
	readers sync.WaitGroup
	done    chan struct{}
}

func startUDPGate(t *testing.T, backend string) *udpGate {
	t.Helper()
	remote, err := net.ResolveUDPAddr("udp4", backend)
	if err != nil {
		t.Fatal(err)
	}
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	gate := &udpGate{front: front, backend: remote, peers: make(map[string]*net.UDPConn), blocked: make(map[string]bool), done: make(chan struct{})}
	go func() {
		defer close(gate.done)
		var buffer [65535]byte
		for {
			n, client, err := front.ReadFromUDP(buffer[:])
			if err != nil {
				return
			}
			key := client.String()
			gate.mu.Lock()
			peer := gate.peers[key]
			if peer == nil {
				peer, err = net.DialUDP("udp4", nil, remote)
				if err == nil {
					gate.peers[key] = peer
					gate.readers.Add(1)
					go func(peer *net.UDPConn, client *net.UDPAddr, key string) {
						defer gate.readers.Done()
						var reply [65535]byte
						for {
							n, err := peer.Read(reply[:])
							if err != nil {
								return
							}
							gate.mu.Lock()
							drop := gate.blocked[key]
							gate.mu.Unlock()
							if !drop {
								_, _ = front.WriteToUDP(reply[:n], client)
							}
						}
					}(peer, client, key)
				}
			}
			drop := gate.blocked[key]
			gate.mu.Unlock()
			if err == nil && !drop {
				_, _ = peer.Write(buffer[:n])
			}
		}
	}()
	return gate
}

func (g *udpGate) blockExisting() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for key := range g.peers {
		g.blocked[key] = true
	}
}
func (g *udpGate) unblock() { g.mu.Lock(); g.blocked = make(map[string]bool); g.mu.Unlock() }
func (g *udpGate) close() {
	g.front.Close()
	<-g.done
	g.mu.Lock()
	for _, peer := range g.peers {
		peer.Close()
	}
	g.mu.Unlock()
	g.readers.Wait()
}

func TestH3BlackholedSetupRecoversOnNewPathAndPreservesExistingStream(t *testing.T) {
	var dials atomic.Int64
	target := testDestination(t, func(c net.Conn) { dials.Add(1); io.Copy(c, c) })
	server := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
	node := httptest.NewUnstartedServer(server)
	node.EnableHTTP2 = true
	node.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	node.StartTLS()
	defer node.Close()
	startNativeH3(t, node, server)
	gate := startUDPGate(t, node.Listener.Addr().String())
	defer gate.close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: node.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient("https://"+gate.front.LocalAddr().String(), "alice", "secret", ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTransport("h3-post"); err != nil {
		t.Fatal(err)
	}
	client.ConnectTimeout = 3 * time.Second
	exchange := func(stream *openStream, message string) {
		t.Helper()
		sent := make(chan error, 1)
		go func() { _, err := stream.writer.Write([]byte(message)); sent <- err }()
		read := make(chan error, 1)
		go func() {
			buffer := make([]byte, len(message))
			_, err := io.ReadFull(stream.response.Body, buffer)
			if err == nil && string(buffer) != message {
				err = io.ErrUnexpectedEOF
			}
			read <- err
		}()
		for range 2 {
			select {
			case err := <-sent:
				if err != nil {
					t.Fatal(err)
				}
			case err := <-read:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				stream.close()
				t.Fatal("echo on preserved/new stream stalled")
			}
		}
	}
	old, err := client.openTunnel(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	defer old.close()
	exchange(old, "before")
	gate.blockExisting()
	client.ConnectTimeout = 500 * time.Millisecond
	started := time.Now()
	failed, err := client.openTunnel(context.Background(), target)
	if failed != nil {
		failed.close()
		t.Fatal("blackholed request succeeded")
	}
	if err == nil || time.Since(started) > 2*time.Second {
		t.Fatalf("setup deadline not respected: %v", err)
	}
	if dials.Load() != 1 {
		t.Fatal("timed-out request was replayed")
	}
	client.ConnectTimeout = 3 * time.Second
	recovered, err := client.openTunnel(context.Background(), target)
	if err != nil {
		t.Fatal("new request reused dead QUIC path:", err)
	}
	defer recovered.close()
	exchange(recovered, "new")
	gate.unblock()
	exchange(old, "preserved")
	if dials.Load() != 2 {
		t.Fatalf("unexpected destination dials: %d", dials.Load())
	}
}
