package tunnel

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func limitRequest(t *testing.T, c *Client, target, label string) (*http.Response, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	reader, writer := io.Pipe()
	t.Cleanup(func() { cancel(); reader.Close(); writer.Close() })
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, c.ServerURL.String(), reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = target
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
	req.Header.Set("X-Test-Request", label)
	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp, cancel
}

func TestTunnelLimitRejectsBeforeDialAndRecovers(t *testing.T) {
	var connections atomic.Int64
	target := testDestination(t, func(c net.Conn) { connections.Add(1); _, _ = io.Copy(io.Discard, c) })
	firstDone := make(chan struct{})
	s := &Server{Username: "alice", Password: "secret", AllowPrivate: true, MaxTunnels: 1, Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })}
	client, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Request") == "first" {
			defer close(firstDone)
		}
		s.ServeHTTP(w, r)
	}))
	first, cancelFirst := limitRequest(t, client, target, "first")
	if first.StatusCode != 200 {
		t.Fatal(first.StatusCode)
	}
	denied, cancelDenied := limitRequest(t, client, target, "denied")
	cancelDenied()
	denied.Body.Close()
	if denied.StatusCode != 503 {
		t.Fatalf("overload status %d", denied.StatusCode)
	}
	// Saturation cannot turn rejected probes into a tunnel-capacity oracle.
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		req := httptest.NewRequest(method, "https://example.com/", nil)
		req.ProtoMajor = 2
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("cover changed under load: %d", rr.Code)
		}
	}
	cancelFirst()
	first.Body.Close()
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled slot not released")
	}
	third, cancelThird := limitRequest(t, client, target, "third")
	if third.StatusCode != 200 {
		t.Fatalf("capacity did not recover: %d", third.StatusCode)
	}
	cancelThird()
	third.Body.Close()
	// Handler admission may precede the accept goroutine's accounting. Wait for
	// the listener handlers after cancellation, using a bounded yield loop.
	deadline := time.Now().Add(time.Second)
	for connections.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := connections.Load(); got != 2 {
		t.Fatalf("expected exactly two destination connections, got %d", got)
	}
}
func TestTunnelLimitReleasedAfterDialFailure(t *testing.T) {
	s := &Server{Username: "alice", Password: "secret", AllowPrivate: true, MaxTunnels: 1, DialTimeout: time.Second}
	client, _ := testClient(t, s)
	unused, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unavailable := unused.Addr().String()
	unused.Close()
	failed, cancel := limitRequest(t, client, unavailable, "failed")
	io.Copy(io.Discard, failed.Body)
	failed.Body.Close()
	cancel()
	if failed.StatusCode != 502 {
		t.Fatal(failed.StatusCode)
	}
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	next, cancelNext := limitRequest(t, client, target, "next")
	defer cancelNext()
	if next.StatusCode != 200 {
		t.Fatalf("dial failure leaked admission: %d", next.StatusCode)
	}
}
func TestTunnelAdmissionParallelBound(t *testing.T) {
	// Exercise simultaneous admission while every admitted worker holds its
	// slot until all contenders have tried; successes must equal the limit.
	const limit = 7
	s := &Server{MaxTunnels: limit}
	var contenders sync.WaitGroup
	var workers sync.WaitGroup
	var admitted atomic.Int64
	release := make(chan struct{})
	for i := 0; i < 100; i++ {
		contenders.Add(1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			ok := s.acquireTunnel()
			if ok {
				admitted.Add(1)
			}
			contenders.Done()
			if ok {
				<-release
				s.activeTunnels.Add(-1)
			}
		}()
	}
	contenders.Wait()
	close(release)
	workers.Wait()
	if admitted.Load() != limit {
		t.Fatalf("admitted %d", admitted.Load())
	}
	if !s.acquireTunnel() {
		t.Fatal("capacity did not recover")
	}
	s.activeTunnels.Add(-1)
}
