//go:build neqo && nss && cgo && linux && amd64

package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

func TestNeqoNativeSOCKSLargeHalfClose(t *testing.T) {
	for _, mode := range []string{"h3-post", "h3-connect"} {
		t.Run(mode, func(t *testing.T) { testNeqoNativeSOCKSLargeHalfClose(t, mode) })
	}
}

func testNeqoNativeSOCKSLargeHalfClose(t *testing.T, mode string) {
	var dials atomic.Int64
	target := testDestination(t, func(conn net.Conn) { dials.Add(1); data, _ := io.ReadAll(conn); _, _ = conn.Write(data) })
	server := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
	client, addr := testClient(t, server)
	node := setupEndpoint(t, client, server)
	startNativeH3(t, node, server)
	usePrimary(t, client, node.URL)
	if err := client.SetServerIdentity("example.com", tlsidentity.Pin(node.Certificate())); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTransport(mode); err != nil {
		t.Fatal(err)
	}
	if err := client.SetQUICBackend("neqo", false, time.Second); err != nil {
		t.Fatal(err)
	}
	for round := range 2 {
		conn, code := connectSOCKS(t, addr, target)
		if code != 0 {
			t.Fatal("SOCKS", code)
		}
		payload := make([]byte, 2<<20)
		for i := range payload {
			payload[i] = byte((i*19 + i/32768 + round) % 251)
		}
		done := make(chan error, 1)
		go func() {
			_, err := conn.Write(payload)
			if err == nil {
				err = conn.(*net.TCPConn).CloseWrite()
			}
			done <- err
		}()
		got, err := io.ReadAll(conn)
		conn.Close()
		if err != nil || !bytes.Equal(payload, got) {
			t.Fatal("half-close data", len(got), err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if dials.Load() != 2 {
		t.Fatal("destination dial count", dials.Load())
	}
	if err := client.SetTLSBackend("go"); err == nil {
		t.Fatal("Neqo silently accepted Go TLS")
	}
	if err := client.SetTransport("h2-connect"); err == nil || client.nativeTransport != mode {
		t.Fatal("incompatible transition did not roll back")
	}
}
func TestNeqoBlockedUDPFallbackH2AndNoFallback(t *testing.T) {
	for _, mode := range []string{"h3-post", "h3-connect"} {
		t.Run(mode, func(t *testing.T) { testNeqoBlockedUDPFallbackH2AndNoFallback(t, mode) })
	}
}

func testNeqoBlockedUDPFallbackH2AndNoFallback(t *testing.T, mode string) {
	for _, fallback := range []bool{false, true} {
		name := "disabled"
		if fallback {
			name = "h2"
		}
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int64
			server := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
			client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); server.ServeHTTP(w, r) }))
			udp, err := net.ListenPacket("udp", client.ServerURL.Host)
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			go func() {
				p := make([]byte, 2048)
				for {
					if _, _, err := udp.ReadFrom(p); err != nil {
						return
					}
				}
			}()
			if err := client.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			if err := client.SetQUICBackend("neqo", fallback, 150*time.Millisecond); err != nil {
				t.Fatal(err)
			}
			target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			started := time.Now()
			stream, err := client.openTunnel(context.Background(), target)
			elapsed := time.Since(started)
			if elapsed < 100*time.Millisecond || elapsed > 2*time.Second {
				t.Fatal("UDP timeout budget", elapsed, err)
			}
			if !fallback {
				if err == nil || requests.Load() != 0 {
					t.Fatal("unrequested fallback", err, requests.Load())
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer stream.close()
			if stream.response.ProtoMajor != 2 {
				t.Fatal("fallback did not negotiate H2")
			}
			payload := []byte("fallback body must be sent once")
			go func() { _, _ = stream.writer.Write(payload); stream.writer.Close() }()
			got, err := io.ReadAll(stream.response.Body)
			if err != nil || !bytes.Equal(payload, got) {
				t.Fatal("fallback payload", got, err)
			}
			if requests.Load() != 1 {
				t.Fatal("replayed HTTP request", requests.Load())
			}
		})
	}
}
func TestNeqoTrustFailureDoesNotDowngrade(t *testing.T) {
	var tcpCalls atomic.Int64
	server := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { tcpCalls.Add(1); server.ServeHTTP(w, r) }))
	node := setupEndpoint(t, client, server)
	startNativeH3(t, node, server)
	usePrimary(t, client, node.URL)
	if err := client.SetServerIdentity("wrong.example", ""); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTransport("h3-post"); err != nil {
		t.Fatal(err)
	}
	if err := client.SetQUICBackend("neqo", true, time.Second); err != nil {
		t.Fatal(err)
	}
	pool := client.transport.(*identityPool)
	variant, err := pool.forPolicy(client.ServerURL.Scheme+"://"+client.ServerURL.Host, client.identity)
	if err != nil {
		t.Fatal(err)
	}
	fallback := variant.(postTransport).tlsTransport.(*neqoFallbackTransport)
	fallback.h2 = &countRoundTrip{tlsTransport: fallback.h2, calls: &tcpCalls}
	if _, err := client.openTunnel(context.Background(), "example.org:443"); err == nil {
		t.Fatal("bad SNI accepted")
	}
	if tcpCalls.Load() != 0 {
		t.Fatal("TLS failure reached H2")
	}
}

type countRoundTrip struct {
	tlsTransport
	calls *atomic.Int64
}

func (t *countRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return t.tlsTransport.RoundTrip(r)
}
