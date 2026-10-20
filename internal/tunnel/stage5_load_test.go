package tunnel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStage5CoverConcurrencyBudgetAndTunnelIsolation(t *testing.T) {
	for _, managed := range []bool{false, true} {
		name := "legacy"
		if managed {
			name = "managed"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			var calls atomic.Int64
			s := &Server{Username: "alice", Password: "secret", MaxCoverRequests: 2, MaxTunnels: 1}
			if managed {
				s.Access = accessController(t)
			}
			s.Cover = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				entered <- struct{}{}
				<-release
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("public"))
			})
			request := func(method string) *http.Request {
				r := httptest.NewRequest(method, "https://cover.example/", nil)
				r.ProtoMajor = 2
				return r
			}
			results := make(chan int, 2)
			for i := 0; i < cap(entered); i++ {
				go func() {
					w := httptest.NewRecorder()
					s.ServeHTTP(w, request(http.MethodGet))
					results <- w.Code
				}()
			}
			for i := 0; i < cap(entered); i++ {
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("public handler did not accept capacity")
				}
			}
			if s.activeCoverRequests.Load() != 2 || s.activeTunnels.Load() != 0 {
				t.Fatal("public request limit did not reserve exactly two cover slots")
			}

			// An overload response is independent of the request's knowledge
			// of proxy credentials, and it must never cache as a normal page.
			overloaded := func(r *http.Request) (int, string) {
				w := httptest.NewRecorder()
				s.ServeHTTP(w, r)
				if w.Header().Get("Cache-Control") != "no-store" ||
					w.Header().Get("Retry-After") != "1" {
					t.Error("missing retry and no-store overload headers")
				}
				return w.Code, w.Body.String()
			}
			publicCode, publicBody := overloaded(request(http.MethodGet))
			probe := request(http.MethodConnect)
			probe.Host = "target.example:443"
			probe.Header.Set("Proxy-Authorization", stage2Basic("alice", "invalid"))
			probeCode, probeBody := overloaded(probe)
			if publicCode != http.StatusServiceUnavailable || probeCode != publicCode ||
				probeBody != publicBody {
				t.Fatal("cover resource denial depended on private probe")
			}

			// A high-concurrency burst must not increase live site handlers
			// or consume even one of the authenticated tunnel admission slots.
			var wg sync.WaitGroup
			failures := make(chan error, 64)
			for i := 0; i < cap(failures); i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					w := httptest.NewRecorder()
					s.ServeHTTP(w, request(http.MethodGet))
					if w.Code != http.StatusServiceUnavailable {
						failures <- fmt.Errorf("overload status %d", w.Code)
					}
				}()
			}
			wg.Wait()
			close(failures)
			for err := range failures {
				t.Error(err)
			}
			if calls.Load() != 2 || s.activeCoverRequests.Load() != 2 ||
				s.activeTunnels.Load() != 0 {
				t.Fatalf("cover limit bypass: calls=%d cover=%d tunnels=%d",
					calls.Load(), s.activeCoverRequests.Load(), s.activeTunnels.Load())
			}

			// Capacity accounting for authenticated work remains independent
			// of the busy cover; no destination dial can occur here.
			s.activeTunnels.Store(1)
			auth := request(http.MethodConnect)
			auth.Host = "target.example:443"
			password := "secret"
			if managed {
				password = accessAlice
			}
			auth.Header.Set("Proxy-Authorization", stage2Basic("alice", password))
			w := httptest.NewRecorder()
			s.ServeHTTP(w, auth)
			if w.Code != http.StatusServiceUnavailable || s.activeTunnels.Load() != 1 {
				t.Fatalf("authenticated tunnel limit changed: %d %d", w.Code, s.activeTunnels.Load())
			}
			s.activeTunnels.Store(0)

			close(release)
			released = true
			for i := 0; i < cap(results); i++ {
				select {
				case code := <-results:
					if code != http.StatusOK {
						t.Fatalf("admitted public handler failed: %d", code)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("public handler did not release its slot")
				}
			}
			if s.activeCoverRequests.Load() != 0 {
				t.Fatal("public cover slots were not released")
			}
			w = httptest.NewRecorder()
			s.ServeHTTP(w, request(http.MethodGet))
			if w.Code != http.StatusOK || w.Body.String() != "public" {
				t.Fatalf("public cover failed recovery: %d %q", w.Code, w.Body.String())
			}
		})
	}
}

func TestStage5CoverCancellationReleasesCapacity(t *testing.T) {
	entered := make(chan struct{})
	var calls atomic.Int64
	s := &Server{MaxCoverRequests: 1}
	s.Cover = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(entered)
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest(http.MethodGet, "https://cover.example/", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeHTTP(httptest.NewRecorder(), r)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("cover did not begin")
	}
	if s.activeCoverRequests.Load() != 1 {
		t.Fatal("public request not counted")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled cover retained concurrency slot")
	}
	if s.activeCoverRequests.Load() != 0 {
		t.Fatal("cancelled cover retained concurrency slot")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://cover.example/", nil))
	if w.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("cancelled cover blocked future requests: %d", w.Code)
	}
}

func TestStage5CoverPanicsReleaseCapacity(t *testing.T) {
	s := &Server{MaxCoverRequests: 1, Cover: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("intentional cover panic")
	})}
	func() {
		defer func() {
			if got := recover(); got != "intentional cover panic" {
				t.Error("expected test panic from cover")
			}
		}()
		s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://cover.example/", nil))
	}()
	if s.activeCoverRequests.Load() != 0 {
		t.Fatal("cover panic leaked admission slot")
	}
}

// Exercises the admission boundary over real loopback TLS sockets; a blocked
// public request must not cause the server to start a second cover handler.
func TestStage5CoverBudgetOverRealTLS(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		mode := "h1"
		if h2 {
			mode = "h2"
		}
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			s := &Server{MaxCoverRequests: 1}
			var requests atomic.Int64
			s.Cover = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					close(entered)
					<-release
				}
				w.WriteHeader(http.StatusNoContent)
			})
			server := httptest.NewUnstartedServer(s)
			server.EnableHTTP2 = h2
			server.StartTLS()
			defer server.Close()
			client := server.Client()
			client.Timeout = 4 * time.Second
			completed := make(chan error, 1)
			go func() {
				resp, err := client.Get(server.URL + "/")
				if err != nil {
					completed <- err
					return
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					completed <- fmt.Errorf("first response: %d", resp.StatusCode)
				} else {
					completed <- nil
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("first TLS cover did not start")
			}
			resp, err := client.Get(server.URL + "/")
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("TLS cover overload mismatch: %d", resp.StatusCode)
			}
			_ = resp.Body.Close()
			if requests.Load() != 1 {
				t.Fatal("second TLS cover handler bypassed budget")
			}
			close(release)
			select {
			case err := <-completed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("first TLS cover did not complete")
			}
			if s.activeCoverRequests.Load() != 0 {
				t.Fatal("TLS cover retained a request slot")
			}
		})
	}
}

func BenchmarkStage5PublicCoverAdmission(b *testing.B) {
	s := &Server{MaxCoverRequests: 64, Cover: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	req := httptest.NewRequest(http.MethodGet, "https://cover.example/", nil)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			s.cover(w, req)
			if w.Code != http.StatusNoContent && w.Code != http.StatusServiceUnavailable {
				b.Errorf("unexpected cover response %d", w.Code)
			}
		}
	})
}
