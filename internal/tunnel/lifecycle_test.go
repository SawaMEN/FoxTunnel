package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testClient(t testing.TB, handler http.Handler) (*Client, string) {
	t.Helper()
	client, addr, _ := testClientWithStop(t, handler)
	return client, addr
}

func testClientWithStop(t testing.TB, handler http.Handler) (*Client, string, func()) {
	c, addr, start, stop := testClientWithDeferredStart(t, handler)
	start()
	return c, addr, stop
}
func testClientWithDeferredStart(t testing.TB, handler http.Handler) (*Client, string, func(), func()) {
	t.Helper()
	upstream := httptest.NewUnstartedServer(handler)
	upstream.EnableHTTP2 = true
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	ca := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(upstream.URL, "alice", "secret", ca)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	stop := func() {
		cancel()
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("SOCKS workers did not stop")
		}
	}
	t.Cleanup(stop)
	ready := make(chan struct{})
	var once sync.Once
	start := func() { once.Do(func() { close(ready) }) }
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			return
		case <-ready:
		}
		_ = client.ServeContext(ctx, listener)
	}()
	return client, listener.Addr().String(), start, stop
}

func connectSOCKS(t testing.TB, addr, target string) (net.Conn, byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		t.Fatal(err)
	}
	host, port, err := splitTarget(target)
	if err != nil {
		t.Fatal(err)
	}
	p, err := net.LookupPort("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
	request = binary.BigEndian.AppendUint16(request, uint16(p))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	return conn, reply[1]
}

func testDestination(t testing.TB, handle func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return l.Addr().String()
}

func TestConnectSetupTimeout(t *testing.T) {
	done := make(chan struct{})
	client, addr := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done(); close(done) }))
	client.ConnectTimeout = 100 * time.Millisecond
	conn, code := connectSOCKS(t, addr, "example.com:443")
	defer conn.Close()
	if code == 0 {
		t.Fatal("stalled CONNECT succeeded")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT context leaked")
	}
}

func TestStreamOutlivesSetupTimeoutAndHalfClose(t *testing.T) {
	target := testDestination(t, func(c net.Conn) { data, _ := io.ReadAll(c); _, _ = c.Write(data) })
	client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
	client.ConnectTimeout = 300 * time.Millisecond
	conn, code := connectSOCKS(t, addr, target)
	if code != 0 {
		t.Fatalf("SOCKS code %d", code)
	}
	time.Sleep(2 * client.ConnectTimeout)
	if _, err := conn.Write([]byte("after setup timeout")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "after setup timeout" {
		t.Fatalf("half-close reply %q, %v", got, err)
	}
}

func TestCancelledStreamClosesSilentDestination(t *testing.T) {
	closed := make(chan struct{})
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c); close(closed) })
	_, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
	conn, code := connectSOCKS(t, addr, target)
	if code != 0 {
		t.Fatalf("SOCKS code %d", code)
	}
	// RST models an aborted application, rather than graceful TCP half-close.
	_ = conn.(*net.TCPConn).SetLinger(0)
	_ = conn.Close()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("silent destination was not released")
	}
}

func TestParallelStreams(t *testing.T) {
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	_, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, code := connectSOCKS(t, addr, target)
			defer conn.Close()
			if code != 0 {
				t.Errorf("SOCKS code %d", code)
				return
			}
			msg := bytes.Repeat([]byte("fox"), 32768)
			done := make(chan error, 1)
			go func() { _, err := conn.Write(msg); done <- err }()
			got := make([]byte, len(msg))
			_, err := io.ReadFull(conn, got)
			if err != nil || !bytes.Equal(got, msg) {
				t.Errorf("corrupt stream: %v", err)
			}
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

// Persistent stream echo measures both upload and download on loopback. It is
// not an Internet/DPI benchmark. The payload size is counted once (roundtrip).
func BenchmarkTunnelRoundTrip(b *testing.B) { benchmarkTunnelRoundTrip(b, "go") }

func benchmarkTunnelRoundTrip(b *testing.B, backend string) {
	benchmarkTunnelOptions(b, backend, false)
}

func benchmarkTunnelOptions(b *testing.B, backend string, padding bool) {
	benchmarkNativeOptions(b, backend, padding, "h2-connect")
}

func benchmarkNativeOptions(b *testing.B, backend string, padding bool, mode string, receiveProfile ...string) {
	target := testDestination(b, func(c net.Conn) { _, _ = io.Copy(c, c) })
	server := &Server{Username: "alice", Password: "secret", AllowPrivate: true, Padding: padding}
	client, addr := testClient(b, server)
	if isH3Transport(mode) {
		node := setupEndpoint(b, client, server)
		startNativeH3(b, node, server)
		client.ServerURL = nodeURL(b, node.URL)
	}
	client.Padding = padding
	selected := backend
	if backend == "neqo" {
		selected = "auto"
	}
	if err := client.SetTLSBackend(selected); err != nil {
		b.Fatal(err)
	}
	if err := client.SetTransport(mode); err != nil {
		b.Fatal(err)
	}
	if backend == "neqo" {
		if err := client.SetQUICBackend("neqo", false, 2*time.Second); err != nil {
			b.Fatal(err)
		}
	}
	if len(receiveProfile) > 0 {
		if err := client.SetHTTP2ReceiveProfile(receiveProfile[0]); err != nil {
			b.Fatal(err)
		}
	}
	for _, size := range []int{64, 1 << 20} {
		b.Run(stringSize(size), func(b *testing.B) {
			conn, code := connectSOCKS(b, addr, target)
			defer conn.Close()
			if code != 0 {
				b.Fatal(code)
			}
			_ = conn.SetDeadline(time.Time{})
			payload := bytes.Repeat([]byte{0x42}, size)
			got := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				done := make(chan error, 1)
				go func() { _, err := conn.Write(payload); done <- err }()
				if _, err := io.ReadFull(conn, got); err != nil {
					b.Fatal(err)
				}
				if err := <-done; err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if !bytes.Equal(got, payload) {
				b.Fatal("corrupt payload")
			}
		})
	}
}
func stringSize(size int) string {
	if size == 64 {
		return "64B"
	}
	return "1MiB"
}

func TestTLSResumptionOnReconnect(t *testing.T) {
	resumed := make(chan bool, 2)
	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resumed <- r.TLS.DidResume
		_, _ = w.Write([]byte("site"))
	}))
	// This test verifies the Go TLS session cache, not the NSS adapter.
	if err := client.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodGet, client.ServerURL.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got := <-resumed; got != (i == 1) {
			t.Fatalf("connection %d resumed=%v", i, got)
		}
		client.transport.CloseIdleConnections()
	}
}

func BenchmarkPaddedTunnelRoundTrip(b *testing.B) { benchmarkTunnelOptions(b, "go", true) }

func nodeURL(t testing.TB, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
