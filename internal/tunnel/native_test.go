package tunnel

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

func TestNativeTransports(t *testing.T) { testNativeTransports(t, "go") }
func testNativeTransports(t *testing.T, backend string) {
	for _, mode := range []string{"h2-post", "wss", "h3-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		if backend == "nss" && mode == "h3-post" {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			target := testDestination(t, func(c net.Conn) { data, _ := io.ReadAll(c); _, _ = c.Write(data) })
			server := &Server{Username: "alice", Password: "secret", AllowPrivate: true, Padding: true}
			client, addr := testClient(t, server)
			if mode == "h3-post" {
				node := setupEndpoint(t, client, server)
				startNativeH3(t, node, server)
				usePrimary(t, client, node.URL)
			}
			if err := client.SetTLSBackend(backend); err != nil {
				t.Fatal(err)
			}
			if err := client.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			client.Padding = true
			client.ConnectTimeout = 200 * time.Millisecond
			stream, setupErr := client.openTunnel(context.Background(), target)
			if setupErr != nil {
				t.Fatal(setupErr)
			}
			stream.close()
			for range 2 {
				conn, code := connectSOCKS(t, addr, target)
				if code != 0 {
					t.Fatal("setup", code)
				}
				time.Sleep(250 * time.Millisecond)
				payload := bytes.Repeat([]byte("native transport"), 20000)
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				conn.(*net.TCPConn).CloseWrite()
				got, err := io.ReadAll(conn)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal("half-close/large data", len(got), err)
				}
				conn.Close()
			}
		})
	}
}

func TestNativeDiscoveredBond(t *testing.T) {
	for _, mode := range []string{"h2-post", "wss", "h3-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) { testBondedSOCKSNative(t, "go", 8, true, mode) })
	}
}

func TestNativeVerificationBeforeCredentials(t *testing.T) {
	testNativeVerificationBeforeCredentials(t, "go")
}
func testNativeVerificationBeforeCredentials(t *testing.T, backend string, receiveProfile ...string) {
	for _, mode := range []string{"h2-connect", "h2-post", "wss", "h3-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		if len(receiveProfile) > 0 && (mode == "wss" || mode == "h3-post") {
			continue
		}
		if backend == "nss" && mode == "h3-post" {
			continue
		}
		for _, failure := range []string{"ca", "pin", "sni"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				var called atomic.Bool
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Store(true); w.WriteHeader(404) })
				c, _ := testClient(t, handler)
				if mode == "h3-post" {
					server := &Server{Username: "alice", Password: "secret", Cover: handler}
					node := setupEndpoint(t, c, server)
					startNativeH3(t, node, server)
					usePrimary(t, c, node.URL)
				}
				if failure == "ca" {
					c.tlsConfig.RootCAs = x509.NewCertPool()
				}
				if err := c.SetTLSBackend(backend); err != nil {
					t.Fatal(err)
				}
				if failure == "pin" {
					if err := c.SetServerIdentity("", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); err != nil {
						t.Fatal(err)
					}
				}
				if failure == "sni" {
					if err := c.SetServerIdentity("wrong.example", ""); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.SetTransport(mode); err != nil {
					t.Fatal(err)
				}
				if len(receiveProfile) > 0 {
					if err := c.SetHTTP2ReceiveProfile(receiveProfile[0]); err != nil {
						t.Fatal(err)
					}
				}
				if xhttp.IsMode(mode) {
					if err := c.SetXHTTPSettings("/api/custom", "route.example"); err != nil {
						t.Fatal(err)
					}
				}
				stream, err := c.openTunnel(context.Background(), "example.com:443")
				if err == nil {
					stream.close()
					t.Fatal("invalid identity accepted")
				}
				if called.Load() {
					t.Fatal("HTTP credentials sent before TLS verification")
				}
			})
		}
	}
}

func TestNativePolicyAndCancellation(t *testing.T) {
	for _, mode := range []string{"h2-post", "wss", "h3-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			s := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
			c, _ := testClient(t, s)
			// A separate origin gets a fresh verified SNI/pin transport, including WSS.
			node := setupEndpoint(t, c, s)
			if mode == "h3-post" {
				startNativeH3(t, node, s)
				usePrimary(t, c, node.URL)
			}
			if err := c.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			view := identityView{pool: c.transport.(*identityPool), policies: map[string]tlsidentity.Policy{node.URL: {SNI: "example.com", PinSHA256: tlsidentity.Pin(node.Certificate())}}}
			r, _ := http.NewRequest("GET", node.URL, nil)
			resp, err := view.RoundTrip(r)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			done := make(chan struct{})
			target := testDestination(t, func(conn net.Conn) { defer close(done); _, _ = io.Copy(io.Discard, conn) })
			ctx, cancel := context.WithCancel(context.Background())
			stream, err := c.openTunnel(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			cancel()
			stream.close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("cancelled stream leaked destination")
			}
			if err := c.SetTransport("xray"); err == nil {
				t.Fatal("unknown mode accepted")
			}
		})
	}
}

func startNativeH3(t testing.TB, endpoint *httptest.Server, server *Server) {
	t.Helper()
	udp, err := net.ListenPacket("udp", endpoint.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.ServeHTTP3(ctx, udp, endpoint.TLS, 32) }()
	t.Cleanup(func() {
		cancel()
		udp.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("HTTP/3 server leaked")
		}
	})
}

func BenchmarkNativeTransports(b *testing.B) {
	for _, mode := range []string{"h2-connect", "h2-post", "wss", "h3-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		b.Run(mode, func(b *testing.B) { benchmarkNativeOptions(b, "go", false, mode) })
	}
}

func TestNativeSetupTimeout(t *testing.T) {
	for _, mode := range []string{"h2-post", "wss", "h3-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			done := make(chan struct{}, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done(); done <- struct{}{} })
			c, _ := testClient(t, handler)
			if mode == "h3-post" {
				s := &Server{Username: "alice", Password: "secret", Cover: handler}
				node := setupEndpoint(t, c, s)
				startNativeH3(t, node, s)
				usePrimary(t, c, node.URL)
				c.Password = "wrong"
			}
			if err := c.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			c.ConnectTimeout = 100 * time.Millisecond
			started := time.Now()
			stream, err := c.openTunnel(context.Background(), "example.com:443")
			if err == nil {
				stream.close()
				t.Fatal("stalled setup succeeded")
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("setup ignored timeout")
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("setup request leaked")
			}
		})
	}
}

func TestNativeProbeCover(t *testing.T) {
	s := &Server{Username: "alice", Password: "secret", Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get(targetHeader) != "" {
			t.Error("private headers reached cover")
		}
		w.WriteHeader(418)
	})}
	for _, path := range []string{postPath, wsPath, xhttp.Path, xhttp.Path + "00000000-0000-4000-8000-000000000001"} {
		for _, proto := range []int{1, 2, 3} {
			r := httptest.NewRequest("POST", "https://main.example"+path, nil)
			r.ProtoMajor = proto
			if path == wsPath {
				r.Method = "GET"
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
			}
			r.Header.Set("Proxy-Authorization", basicAuth("alice", "wrong"))
			r.Header.Set(targetHeader, "127.0.0.1:22")
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 418 || s.activeTunnels.Load() != 0 || s.activeWebSockets.Load() != 0 {
				t.Fatal("unauthenticated probe reached tunnel", path, proto, w.Code)
			}
		}
	}
}

func TestXHTTPIdleClosePreservesActiveStream(t *testing.T) {
	for _, mode := range []string{"xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			c, _ := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
			if err := c.SetTransport(mode); err != nil {
				t.Fatal(err)
			}
			stream, err := c.openTunnel(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.close()
			transport := c.transport.(*identityPool).base.(*xhttpTransport)
			transport.CloseIdleConnections()
			data := []byte("active carrier survives idle close")
			if _, err := stream.writer.Write(data); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(data))
			if _, err := io.ReadFull(stream.response.Body, got); err != nil || !bytes.Equal(got, data) {
				t.Fatal("active stream cut off", err)
			}
			stream.close()
			deadline := time.Now().Add(time.Second)
			for {
				transport.mu.Lock()
				n := len(transport.carriers)
				transport.mu.Unlock()
				if n == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("idle carrier retained")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
