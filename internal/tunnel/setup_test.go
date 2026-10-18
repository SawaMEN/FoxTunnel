package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func closedProxy(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := "https://" + l.Addr().String()
	l.Close()
	return addr
}
func setupEndpoint(t testing.TB, c *Client, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.EnableHTTP2 = true
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	c.tlsConfig.RootCAs.AddCert(s.Certificate())
	return s
}
func usePrimary(t *testing.T, c *Client, raw string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.ServerURL = u
}

func TestProxyFallbackGo(t *testing.T) { testProxyFallback(t, "go") }
func testProxyFallback(t *testing.T, backend string) {
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true, Padding: true})
	working := client.ServerURL.String()
	usePrimary(t, client, closedProxy(t))
	if err := client.SetFallbackServers([]string{working}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTLSBackend(backend); err != nil {
		t.Fatal(err)
	}
	client.Padding = true
	for i := 0; i < 2; i++ {
		conn, code := connectSOCKS(t, addr, target)
		if code != 0 {
			t.Fatal(code)
		}
		if _, err := conn.Write([]byte("backup payload")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 14)
		_, err := io.ReadFull(conn, got)
		conn.Close()
		if err != nil || string(got) != "backup payload" {
			t.Fatalf("%q %v", got, err)
		}
	}
	if client.preferredEndpoint.Load() != 1 {
		t.Fatal("successful endpoint not preferred")
	}
}
func TestFallbackAfterStalledConnect(t *testing.T) {
	var stalledCalls atomic.Int64
	client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
	working := client.ServerURL.String()
	stalled := setupEndpoint(t, client, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { stalledCalls.Add(1); <-r.Context().Done() }))
	usePrimary(t, client, stalled.URL)
	if err := client.SetFallbackServers([]string{working}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	client.FallbackAttemptTimeout = 300 * time.Millisecond
	client.ConnectTimeout = 2 * time.Second
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	for i := 0; i < 2; i++ {
		conn, code := connectSOCKS(t, addr, target)
		conn.Close()
		if code != 0 {
			t.Fatal(code)
		}
	}
	if stalledCalls.Load() != 1 {
		t.Fatalf("repeated failed origin %d times", stalledCalls.Load())
	}
}
func TestFallbackStopsOnHTTPOrPaddingFailure(t *testing.T) {
	for _, status := range []int{200, 401, 403, 404, 407, 502, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var backupCalls atomic.Int64
			client, addr := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { backupCalls.Add(1); w.WriteHeader(200) }))
			backup := client.ServerURL.String()
			primary := setupEndpoint(t, client, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			usePrimary(t, client, primary.URL)
			client.Padding = true
			if err := client.SetFallbackServers([]string{backup}); err != nil {
				t.Fatal(err)
			}
			if err := client.SetTLSBackend("go"); err != nil {
				t.Fatal(err)
			}
			conn, code := connectSOCKS(t, addr, "example.com:443")
			conn.Close()
			if code == 0 || backupCalls.Load() != 0 {
				t.Fatalf("terminal failure retried: SOCKS=%d backup=%d", code, backupCalls.Load())
			}
		})
	}
}
func TestFallbackStopsOnHostnameFailure(t *testing.T) { testFallbackCertificate(t, "go") }
func testFallbackCertificate(t *testing.T, backend string) {
	var backupCalls atomic.Int64
	client, addr := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { backupCalls.Add(1); w.WriteHeader(200) }))
	backup := client.ServerURL.String()
	primary := setupEndpoint(t, client, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("credentials sent to wrong hostname") }))
	// The httptest certificate has an IP SAN but no localhost SAN. The backup's
	// original IP origin is trusted and would succeed if incorrectly attempted.
	_, port, _ := net.SplitHostPort(primary.Listener.Addr().String())
	usePrimary(t, client, "https://localhost:"+port)
	if err := client.SetFallbackServers([]string{backup}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTLSBackend(backend); err != nil {
		t.Fatal(err)
	}
	conn, code := connectSOCKS(t, addr, "example.com:443")
	conn.Close()
	if code == 0 || backupCalls.Load() != 0 {
		t.Fatalf("verification bypassed with fallback: %d / %d", code, backupCalls.Load())
	}
}
func TestFallbackTotalBudget(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	client, _ := testClient(t, handler)
	other := setupEndpoint(t, client, handler)
	if err := client.SetFallbackServers([]string{other.URL}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	client.ConnectTimeout = 500 * time.Millisecond
	client.FallbackAttemptTimeout = 300 * time.Millisecond
	start := time.Now()
	stream, err := client.openTunnel(context.Background(), "example.com:443")
	if stream != nil {
		stream.close()
		t.Fatal("stalled endpoint accepted")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("budget failure: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("per-origin budgets extended global budget: %v", elapsed)
	}
}
func TestFallbackConfiguration(t *testing.T) {
	client, err := NewClient("https://example.com", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, bad := range [][]string{{"http://backup.example"}, {"https://u:p@backup.example"}, {"https://backup.example/path"}, {"https://backup.example?q=x"}, {"https://EXAMPLE.COM:443/"}, {"https://backup.example", "https://BACKUP.example:443/"}, {"https://a", "https://b", "https://c", "https://d", "https://e", "https://f", "https://g", "https://h"}} {
		if err := client.SetFallbackServers(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	if err := client.SetFallbackServers([]string{"https://backup.example"}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetFallbackServers(nil); err != nil {
		t.Fatal(err)
	}
}
func TestEstablishedStreamIsNeverReplayed(t *testing.T) {
	var backupCalls atomic.Int64
	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("partial"))
	}))
	backup := setupEndpoint(t, client, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { backupCalls.Add(1) }))
	if err := client.SetFallbackServers([]string{backup.URL}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stream, err := client.openTunnel(ctx, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream.response.Body)
	stream.close()
	if err != nil || string(got) != "partial" || backupCalls.Load() != 0 {
		t.Fatalf("stream replayed: %q %v %d", got, err, backupCalls.Load())
	}
}

func TestHTTP1PeerIsTerminalBeforeCredentials(t *testing.T) {
	var primaryCalls, backupCalls atomic.Int64
	client, addr := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { backupCalls.Add(1); w.WriteHeader(200) }))
	working := client.ServerURL.String()
	primary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { primaryCalls.Add(1); w.WriteHeader(200) }))
	defer primary.Close()
	client.tlsConfig.RootCAs.AddCert(primary.Certificate())
	usePrimary(t, client, primary.URL)
	if err := client.SetFallbackServers([]string{working}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	conn, code := connectSOCKS(t, addr, "example.com:443")
	conn.Close()
	if code == 0 || primaryCalls.Load() != 0 || backupCalls.Load() != 0 {
		t.Fatalf("h2 policy violated: %d primary=%d backup=%d", code, primaryCalls.Load(), backupCalls.Load())
	}
}

func TestEndpointSchedulingGo(t *testing.T) { testEndpointScheduling(t, "go") }
func testEndpointScheduling(t *testing.T, backend string) {
	for _, mode := range []string{"round-robin", "least-active"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := testClient(t, &Server{Username: "alice", Password: "secret"})
			handler := func(name string) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Test-Endpoint", name)
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				})
			}
			a := setupEndpoint(t, c, handler("a"))
			b := setupEndpoint(t, c, handler("b"))
			usePrimary(t, c, a.URL)
			if err := c.SetFallbackServers([]string{b.URL}); err != nil {
				t.Fatal(err)
			}
			if err := c.SetBalance(mode); err != nil {
				t.Fatal(err)
			}
			if err := c.SetTLSBackend(backend); err != nil {
				t.Fatal(err)
			}
			streams := make([]*openStream, 0, 6)
			defer func() {
				for _, stream := range streams {
					stream.close()
				}
			}()
			counts := map[string]int{}
			for range 6 {
				stream, err := c.openTunnel(context.Background(), "example.org:443")
				if err != nil {
					t.Fatal(err)
				}
				streams = append(streams, stream)
				counts[stream.response.Header.Get("X-Test-Endpoint")]++
			}
			if counts["a"] != 3 || counts["b"] != 3 {
				t.Fatalf("distribution: %v", counts)
			}
			if mode == "least-active" {
				freed := streams[0].response.Header.Get("X-Test-Endpoint")
				streams[0].close()
				streams[0].close() // Teardown can race or be called twice.
				next, err := c.openTunnel(context.Background(), "example.org:443")
				if err != nil {
					t.Fatal(err)
				}
				streams = append(streams, next)
				if got := next.response.Header.Get("X-Test-Endpoint"); got != freed {
					t.Fatalf("wanted freed endpoint %s, got %s", freed, got)
				}
			}
			for _, stream := range streams {
				stream.close()
			}
			c.schedulerMu.Lock()
			active := c.activeEndpoints
			c.schedulerMu.Unlock()
			for _, n := range active {
				if n != 0 {
					t.Fatalf("leaked active counts: %v", active)
				}
			}
		})
	}
}

func TestConcurrentEndpointReservations(t *testing.T) {
	c := new(Client)
	if err := c.SetBalance("least-active"); err != nil {
		t.Fatal(err)
	}
	const total = 64
	releases := make(chan func(), total)
	var workers sync.WaitGroup
	for range total {
		workers.Go(func() { _, release := c.reserveEndpoint(make([]bool, 4)); releases <- release })
	}
	workers.Wait()
	close(releases)
	for i := range 4 {
		if c.activeEndpoints[i] != total/4 {
			t.Fatalf("unbalanced reservations: %v", c.activeEndpoints)
		}
	}
	for release := range releases {
		release()
		release()
	}
	for _, n := range c.activeEndpoints {
		if n != 0 {
			t.Fatal("reservation leaked")
		}
	}
	if c.SetBalance("random-unknown") == nil {
		t.Fatal("accepted unknown scheduling policy")
	}
}

func TestEndpointCooldownRecovery(t *testing.T) {
	c := new(Client)
	c.endpointResult(0, true)
	index, release := c.reserveEndpoint([]bool{false, false})
	release()
	if index != 1 {
		t.Fatal("selected cooling endpoint over ready endpoint")
	}
	c.endpointResult(1, true)
	index, release = c.reserveEndpoint([]bool{false, false})
	release()
	if index < 0 || index > 1 {
		t.Fatal("all-cooling pool must remain available")
	}
	c.endpointResult(0, false)
	index, release = c.reserveEndpoint([]bool{false, false})
	release()
	if index != 0 {
		t.Fatal("recovered endpoint not selectable")
	}
	for range 20 {
		c.endpointResult(0, true)
	}
	if delay := time.Until(c.endpointRetryAt[0]); delay <= 0 || delay > 30*time.Second {
		t.Fatalf("unbounded cooldown: %v", delay)
	}
	// A cooling peer is still tried when it is the only untried candidate.
	index, release = c.reserveEndpoint([]bool{false, true})
	release()
	if index != 0 {
		t.Fatal("cooldown excluded last recovery candidate")
	}
}
