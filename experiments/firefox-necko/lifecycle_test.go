package firefox

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/quic-go/quic-go"
)

// Keep these native lifecycle gates separate from upload half-close: failure
// in one contract must not hide a failure in another. All I/O uses xpcshell,
// an independent Go proxy and a real TCP destination.
func TestGeckoConcurrentCONNECT(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("set FOXTUNNEL_XPCSHELL to a real Gecko runtime")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			echo := nativeEcho(t)
			server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
			var active, peak, requests atomic.Int32
			var wrong atomic.Bool
			var wrongMu sync.Mutex
			var wrongRequests []string
			wantProtocol := 2
			if mode == "h3-connect" {
				wantProtocol = 3
			}
			cfg := nativeProxy(t, mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "CONNECT" || r.ProtoMajor != wantProtocol || r.Host != echo || r.URL.Path != "" {
					wrong.Store(true)
					wrongMu.Lock()
					wrongRequests = append(wrongRequests, fmt.Sprintf("%s %s host=%s path=%q", r.Method, r.Proto, r.Host, r.URL.Path))
					wrongMu.Unlock()
					http.Error(w, "wrong CONNECT", http.StatusBadRequest)
					return
				}
				requests.Add(1)
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old; old = peak.Load() {
					if peak.CompareAndSwap(old, n) {
						break
					}
				}
				server.ServeHTTP(w, r)
			}))
			listen, stderr := startTestHelper(t, runtime, cfg)
			const count = 12
			ready := make(chan struct{}, count)
			start := make(chan struct{})
			errors := make(chan error, count)
			var release sync.Once
			defer release.Do(func() { close(start) })
			for index := 0; index < count; index++ {
				go func(index int) {
					conn, err := nativeSOCKS(listen, echo)
					ready <- struct{}{}
					if err != nil {
						errors <- err
						return
					}
					defer conn.Close()
					<-start
					// Every byte value, a distinct stream identifier, and several
					// pipe/flow-control windows expose corruption and cross-talk.
					payload := make([]byte, 128<<10)
					for i := range payload {
						payload[i] = byte(i + index*17)
					}
					if _, err := conn.Write(payload); err != nil {
						errors <- err
						return
					}
					received := make([]byte, len(payload))
					if _, err := io.ReadFull(conn, received); err != nil {
						errors <- err
						return
					}
					if !bytes.Equal(received, payload) {
						errors <- fmt.Errorf("stream %d payload differs", index)
						return
					}
					errors <- nil
				}(index)
			}
			for range count {
				select {
				case <-ready:
				case <-time.After(12 * time.Second):
					t.Fatalf("concurrent setup stalled\n%s", stderr.text())
				}
			}
			release.Do(func() { close(start) })
			for range count {
				if err := <-errors; err != nil {
					t.Errorf("concurrent tunnel: %v\n%s", err, stderr.text())
				}
			}
			if wrong.Load() || requests.Load() != count || peak.Load() != count {
				wrongMu.Lock()
				defer wrongMu.Unlock()
				t.Fatalf("concurrency/protocol: requests=%d peak=%d wrong=%v: %v", requests.Load(), peak.Load(), wrong.Load(), wrongRequests)
			}
		})
	}
}

// A timed-out handoff must release both the local connection slot and the
// serialized H3 setup promise. Reuse one helper with a single allowed slot;
// a new helper per attempt would hide both resource leaks.
func testGeckoSetupTimeoutRecovery(t *testing.T, runtime, mode string) {
	t.Helper()
	echo := nativeEcho(t)
	server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
	var requests atomic.Int32
	var wrong atomic.Bool
	cancelled := make(chan error, 2)
	wantProtocol := 2
	if mode == "h3-connect" {
		wantProtocol = 3
	}
	cfg := nativeProxy(t, mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.ProtoMajor != wantProtocol || r.Host != echo || r.URL.Path != "" {
			wrong.Store(true)
		}
		if requests.Add(1) <= 2 {
			// Withhold response headers so the native handoff stays pending.
			// Its setup deadline must cancel this request at the proxy too.
			// Read the request half to observe stream reset directly. An H3
			// request context alone need not wake a handler that never reads.
			_, err := io.Copy(io.Discard, r.Body)
			cancelled <- err
			return
		}
		server.ServeHTTP(w, r)
	}))
	cfg.MaxConnections = 1
	cfg.ConnectTimeoutMS = 2000
	listen, stderr := startTestHelper(t, runtime, cfg)
	for attempt := 1; attempt <= 2; attempt++ {
		if conn, err := nativeSOCKS(listen, echo); err == nil {
			conn.Close()
			t.Fatal("setup succeeded without proxy response headers")
		}
		select {
		case err := <-cancelled:
			if err == nil {
				t.Error("pending CONNECT ended cleanly instead of being cancelled")
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("setup timeout left request %d active at the proxy\n%s", attempt, stderr.text())
		}
		if requests.Load() != int32(attempt) || wrong.Load() {
			t.Fatalf("setup attempt %d: requests=%d wrong protocol=%v\n%s", attempt, requests.Load(), wrong.Load(), stderr.text())
		}
	}
	conn, err := nativeSOCKS(listen, echo)
	if err != nil {
		t.Fatalf("slot or setup queue did not recover: %v\n%s", err, stderr.text())
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte{0, 255, 13, 10, 42, 1}, 6000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal("recovered upload", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil || !bytes.Equal(response, payload) {
		t.Fatalf("recovered binary transfer: %v\n%s", err, stderr.text())
	}
	if requests.Load() != 3 || wrong.Load() {
		t.Fatalf("recovered CONNECT: requests=%d wrong protocol=%v", requests.Load(), wrong.Load())
	}
}

// Independently validate that the withheld-response fixture can observe a
// client reset on each protocol, before blaming a native cancellation failure.
func TestSetupCancellationPeers(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{}, 1)
			reset := make(chan error, 1)
			cfg := nativeProxy(t, mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				started <- struct{}{}
				_, err := io.Copy(io.Discard, r.Body)
				reset <- err
			}))
			client := independentPeerTransport(t, cfg, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			reader, writer := io.Pipe()
			result := make(chan error, 1)
			finished := make(chan struct{})
			t.Cleanup(func() { cancel(); reader.Close(); writer.Close(); <-finished })
			req, err := http.NewRequestWithContext(ctx, "CONNECT", cfg.Server, reader)
			if err != nil {
				// Let cleanup join even when no request goroutine was started.
				close(finished)
				t.Fatal(err)
			}
			req.Host = "127.0.0.1:443"
			go func() {
				defer close(finished)
				response, err := client.RoundTrip(req)
				if response != nil {
					response.Body.Close()
				}
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("independent CONNECT did not reach proxy")
			}
			cancel()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("cancelled CONNECT unexpectedly succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("independent client did not cancel")
			}
			select {
			case err := <-reset:
				if err == nil {
					t.Fatal("proxy saw clean EOF instead of a reset")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("proxy did not observe independent stream reset")
			}
		})
	}
}

func TestGeckoCancellation(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("set FOXTUNNEL_XPCSHELL to a real Gecko runtime")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			echo := nativeEcho(t)
			server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
			cfg := nativeProxy(t, mode, server)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			listen, stderr, finished := startTestHelperContext(t, ctx, runtime, cfg)
			conn, err := nativeSOCKS(listen, echo)
			if err != nil {
				t.Fatalf("active tunnel: %v\n%s", err, stderr.text())
			}
			defer conn.Close()
			cancel()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("cancel did not join the native helper")
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if n, err := conn.Read(one[:]); n != 0 || err == nil {
				t.Fatal("cancelled tunnel remained readable", n, err)
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("cancel left the local stream open")
			}
			if conn, err := net.DialTimeout("tcp", listen, time.Second); err == nil {
				conn.Close()
				t.Fatal("cancel left the SOCKS listener open")
			}
		})
		t.Run("setup-timeout-recovery/"+mode, func(t *testing.T) {
			testGeckoSetupTimeoutRecovery(t, runtime, mode)
		})
	}
}

func TestGeckoH3NoTCPFallback(t *testing.T) {
	runtime := os.Getenv("FOXTUNNEL_XPCSHELL")
	if runtime == "" {
		t.Skip("set FOXTUNNEL_XPCSHELL to a real Gecko runtime")
	}
	var requests atomic.Int32
	server := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true}
	// Deliberately offer only TCP/H2 on the proxy port. A server-side request
	// counter detects fallback even if the client later rejects its protocol.
	cfg := nativeProxy(t, "h2-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		server.ServeHTTP(w, r)
	}))
	cfg.Transport = "h3-connect"
	cfg.ConnectTimeoutMS = 1000
	listen, stderr := startTestHelper(t, runtime, cfg)
	if conn, err := nativeSOCKS(listen, nativeEcho(t)); err == nil {
		conn.Close()
		t.Fatal("H3-only setup succeeded without a QUIC endpoint")
	}
	if requests.Load() != 0 {
		t.Fatalf("sent %d HTTP requests on the TCP fallback\n%s", requests.Load(), stderr.text())
	}
}

func nativeProxy(t *testing.T, mode string, handler http.Handler, quicConfig ...*quic.Config) Config {
	t.Helper()
	return nativeProxyConfigured(t, mode, handler, nil, quicConfig...)
}

func nativeProxyConfigured(t *testing.T, mode string, handler http.Handler, configure func(*httptest.Server), quicConfig ...*quic.Config) Config {
	t.Helper()
	certificate, ca := testCertificate(t)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	if configure != nil {
		configure(server)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	if mode == "h3-connect" {
		udp, err := net.ListenPacket("udp", server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		finished := make(chan struct{})
		go func() { defer close(finished); _ = serveTestH3(ctx, udp, server.TLS, handler, quicConfig...) }()
		t.Cleanup(func() { cancel(); udp.Close(); <-finished })
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), 0600); err != nil {
		t.Fatal(err)
	}
	return Config{Server: server.URL, Username: "u", Password: "p", Transport: mode, Listen: "127.0.0.1:0", CACert: caPath}
}

func nativeEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var copies sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = struct{}{}
			copies.Add(1)
			mu.Unlock()
			go func() {
				defer copies.Done()
				defer conn.Close()
				io.Copy(conn, conn)
				mu.Lock()
				delete(connections, conn)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-accepted
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		copies.Wait()
	})
	return listener.Addr().String()
}

func nativeSOCKS(listen, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", listen, time.Second)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { conn.Close(); return nil, err }
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fail(err)
	}
	if greeting != [2]byte{5, 0} {
		return fail(fmt.Errorf("SOCKS greeting: %v", greeting))
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fail(err)
	}
	ip := net.ParseIP(host).To4()
	n, err := strconv.Atoi(port)
	if ip == nil || err != nil {
		return fail(fmt.Errorf("invalid IPv4 test target"))
	}
	if _, err := conn.Write([]byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(n >> 8), byte(n)}); err != nil {
		return fail(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fail(err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		return fail(fmt.Errorf("SOCKS CONNECT: %v", reply))
	}
	return conn, nil
}
