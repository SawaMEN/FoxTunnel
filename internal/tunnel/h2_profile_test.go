package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/h2profile"
	"github.com/SawaMEN/VetroffProxy/internal/webprofile"
)

// The fixture stops capture after verified application I/O, not on a one-second
// timer that can truncate an otherwise valid exchange on a loaded race runner.
type profileCaptureListener struct {
	net.Listener
	mu      sync.Mutex
	conn    net.Conn
	stopped bool
}

func (l *profileCaptureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.stopped {
		conn.Close()
	} else {
		l.conn = conn
	}
	l.mu.Unlock()
	return conn, nil
}
func (l *profileCaptureListener) stopCapture() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopped = true
	if l.conn != nil {
		l.conn.Close()
	}
}
func (l *profileCaptureListener) Close() error {
	err := l.Listener.Close()
	l.stopCapture()
	return err
}

func TestHTTP2ReceiveProfile(t *testing.T) { testHTTP2ReceiveProfile(t, "go") }
func testHTTP2ReceiveProfile(t *testing.T, backend string, clientProfiles ...string) {
	for _, mode := range []string{"h2-connect", "h2-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			endpoint := httptest.NewTLSServer(http.NotFoundHandler())
			defer endpoint.Close()
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endpoint.Certificate().Raw}), 0600); e != nil {
				t.Fatal(e)
			}
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			observer := &profileCaptureListener{Listener: l}
			defer observer.Close()
			type capture struct {
				p webprofile.Profile
				e error
			}
			result := make(chan capture, 1)
			go func() {
				p, e := webprofile.Capture(observer, &tls.Config{Certificates: endpoint.TLS.Certificates}, &Server{Username: "alice", Password: "secret", AllowPrivate: true}, "test", 10*time.Second)
				result <- capture{p, e}
			}()
			client, e := NewClient("https://"+l.Addr().String(), "alice", "secret", ca)
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			if e = client.SetTLSBackend(backend); e != nil {
				t.Fatal(e)
			}
			if e = client.SetTransport(mode); e != nil {
				t.Fatal(e)
			}
			if len(clientProfiles) > 0 {
				if e := client.SetTLSClientProfile(clientProfiles[0]); e != nil {
					t.Fatal(e)
				}
				// Exercise the identity-specific transport, not just the base
				// pool, and verify that rebuilding it retains the TLS profile.
				sum := sha256.Sum256(endpoint.Certificate().RawSubjectPublicKeyInfo)
				if e := client.SetServerIdentity("", "sha256/"+base64.StdEncoding.EncodeToString(sum[:])); e != nil {
					t.Fatal(e)
				}

			}
			if e = client.SetHTTP2ReceiveProfile(h2profile.Firefox158); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, e := client.openTunnel(ctx, target)
			if e != nil {
				t.Fatal(e)
			}
			payload := bytes.Repeat([]byte("real flow control"), 20000)
			written := make(chan error, 1)
			go func() { _, e := stream.writer.Write(payload); written <- e }()
			got := make([]byte, len(payload))
			_, e = io.ReadFull(stream.response.Body, got)
			stream.close()
			client.Close()
			observer.stopCapture()
			if e != nil || !bytes.Equal(got, payload) {
				t.Fatal("echo", len(got), e)
			}
			if e = <-written; e != nil {
				t.Fatal(e)
			}
			select {
			case r := <-result:
				if r.e != nil {
					t.Fatal(r.e)
				}
				if len(clientProfiles) > 0 && (!reflect.DeepEqual(r.p.Hello.SupportedGroups, []uint16{4588, 29, 23, 24, 25}) || !reflect.DeepEqual(r.p.Hello.KeyShareGroups, []uint16{4588, 29, 23})) {
					t.Fatal("TLS profile lost in the actual carrier/identity transport", r.p.Hello)
				}

				settings := map[uint16]uint32{}
				for _, s := range r.p.Settings {
					settings[s.ID] = s.Value
				}
				if settings[1] != h2profile.HeaderTable || settings[4] != h2profile.StreamWindow || settings[5] != 16384 {
					t.Fatal("wire settings", r.p.Settings)
				}
				if len(r.p.ConnectionWindow) != 1 || r.p.ConnectionWindow[0] != h2profile.ConnectionCredit {
					t.Fatal("wire connection credit", r.p.ConnectionWindow)
				}
				if backend == "nss" {
					// Firefox 158 does not advertise SETTINGS_MAX_HEADER_LIST_SIZE.
					// Go still enforces its private header accounting limit.
					if _, ok := settings[6]; ok {
						t.Fatal("Mozilla H2 unexpectedly advertised the Go header cap", r.p.Settings)
					}
					if len(r.p.Settings) != 4 {
						t.Fatal("Mozilla H2 initial SETTINGS count", r.p.Settings)
					}
					for i, id := range []uint16{1, 2, 4, 5} {
						if r.p.Settings[i].ID != id {
							t.Fatal("Mozilla H2 SETTINGS ordering", r.p.Settings)
						}
					}
				} else if settings[6] != 10<<20 {
					t.Fatal("Go H2 response header limit removed")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("capture did not end")
			}
		})
	}
}

// Exceed both the per-stream window and the 12 MiB total connection window.
// This requires repeated real WINDOW_UPDATE accounting, not only matching a
// first SETTINGS frame. Concurrent streams exercise one shared outer connection.
func TestHTTP2ReceiveProfileCreditRenewal(t *testing.T) {
	testHTTP2ReceiveProfileCreditRenewal(t, "go")
}
func testHTTP2ReceiveProfileCreditRenewal(t *testing.T, backend string, clientProfiles ...string) {
	for _, mode := range []string{"h2-connect", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			var seenMu sync.Mutex
			seen := map[string]bool{}
			server := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
			client, addr := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenMu.Lock()
				seen[r.RemoteAddr] = true
				seenMu.Unlock()
				server.ServeHTTP(w, r)
			}))
			if e := client.SetTLSBackend(backend); e != nil {
				t.Fatal(e)
			}
			if e := client.SetTransport(mode); e != nil {
				t.Fatal(e)
			}
			if len(clientProfiles) > 0 {
				if e := client.SetTLSClientProfile(clientProfiles[0]); e != nil {
					t.Fatal(e)
				}
			}
			if e := client.SetHTTP2ReceiveProfile(h2profile.Firefox158); e != nil {
				t.Fatal(e)
			}
			payload := bytes.Repeat([]byte{1, 3, 5, 7}, 1<<20)
			var conns []net.Conn
			for range 4 {
				c, code := connectSOCKS(t, addr, target)
				if code != 0 {
					t.Fatal("SOCKS", code)
				}
				conns = append(conns, c)
			}
			var wg sync.WaitGroup
			for _, c := range conns {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer c.Close()
					written := make(chan error, 1)
					go func() { _, e := c.Write(payload); written <- e }()
					got := make([]byte, len(payload))
					_, e := io.ReadFull(c, got)
					c.Close()
					if e != nil || !bytes.Equal(got, payload) {
						t.Error("credit renewal echo", e)
					}
					if e = <-written; e != nil {
						t.Error(e)
					}
				}()
			}
			wg.Wait()
			seenMu.Lock()
			defer seenMu.Unlock()
			if len(seen) != 1 {
				t.Fatal("test did not share one outer connection", len(seen))
			}
		})
	}
}
func TestHTTP2ReceiveProfileRollback(t *testing.T) {
	c, _ := testClient(t, http.NotFoundHandler())
	old := c.transport
	if e := c.SetHTTP2ReceiveProfile("unknown"); e == nil || c.transport != old {
		t.Fatal("unknown profile changed state")
	}
	if e := c.SetHTTP2ReceiveProfile(h2profile.Firefox158); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"wss", "h3-post"} {
		if e := c.SetTransport(mode); e == nil || c.nativeTransport != "h2-connect" && c.nativeTransport != "" {
			t.Fatal("incompatible transport changed state")
		}
	}
	if e := c.SetServerIdentity("example.org", ""); e != nil {
		t.Fatal(e)
	}
	if c.transport.(*identityPool).h2ReceiveProfile != h2profile.Firefox158 {
		t.Fatal("identity rebuild lost profile")
	}
	if e := c.SetHTTP2ReceiveProfile("default"); e != nil || c.h2ReceiveProfile != "" {
		t.Fatal("default restore", e)
	}
}

func TestHTTP2ReceiveProfileTLSRejection(t *testing.T) {
	testNativeVerificationBeforeCredentials(t, "go", h2profile.Firefox158)
}
func TestHTTP2ReceiveProfileCancellation(t *testing.T) { testHTTP2ReceiveProfileCancellation(t, "go") }
func testHTTP2ReceiveProfileCancellation(t *testing.T, backend string, clientProfiles ...string) {
	for _, mode := range []string{"h2-connect", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			done := make(chan struct{})
			target := testDestination(t, func(c net.Conn) { defer close(done); _, _ = io.Copy(io.Discard, c) })
			client, _ := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
			if e := client.SetTLSBackend(backend); e != nil {
				t.Fatal(e)
			}
			if e := client.SetTransport(mode); e != nil {
				t.Fatal(e)
			}
			if len(clientProfiles) > 0 {
				if e := client.SetTLSClientProfile(clientProfiles[0]); e != nil {
					t.Fatal(e)
				}
			}
			if e := client.SetHTTP2ReceiveProfile(h2profile.Firefox158); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream, e := client.openTunnel(ctx, target)
			if e != nil {
				t.Fatal(e)
			}
			defer stream.close()
			// A successful open detaches setup cancellation from stream lifetime;
			// explicit stream closure must tear down relay work promptly.
			cancel()
			stream.close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("relay retained after stream close")
			}
		})
	}
}

func BenchmarkHTTP2ReceiveProfile(b *testing.B) {
	for _, mode := range []string{"h2-connect", "xhttp-packet-up"} {
		for _, profile := range []string{"default", h2profile.Firefox158} {
			b.Run(mode+"/"+profile, func(b *testing.B) { benchmarkNativeOptions(b, "go", false, mode, profile) })
		}
	}
}
