package tunnel

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/cluster"
)

type clusterTransport func(*http.Request) (*http.Response, error)

func TestDiscoveryRejectsUnverifiedTLS(t *testing.T) { testDiscoveryRejectsUnverifiedTLS(t, "go") }
func testDiscoveryRejectsUnverifiedTLS(t *testing.T, backend string) {
	var called atomic.Bool
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Store(true); w.WriteHeader(503) }))
	c.tlsConfig.RootCAs = x509.NewCertPool()
	if err := c.SetTLSBackend(backend); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableBondDiscovery(context.Background()); err == nil {
		t.Fatal("unverified coordinator accepted")
	}
	if called.Load() {
		t.Fatal("credentials sent before coordinator verification")
	}
}

func (f clusterTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func (f clusterTransport) CloseIdleConnections()                             {}

func clusterBody(node string) string {
	return `{"v":1,"hub_id":"` + strings.Repeat("ab", 32) + `","valid_for":120,"nodes":[{"url":"` + node + `","weight":4}]}`
}
func forceClusterRefresh(c *Client, expired bool) {
	d := c.bondDiscovery
	d.mu.Lock()
	d.refreshAt = time.Time{}
	if expired {
		d.expires = time.Time{}
	}
	d.mu.Unlock()
}

func TestDiscoveryRefreshFailureAndConcurrentReuse(t *testing.T) {
	c, err := NewClient("https://main.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var calls atomic.Int64
	var status atomic.Int64
	status.Store(200)
	var body atomic.Value
	body.Store(clusterBody("https://a.example"))
	c.transport = clusterTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Host != "main.example" || r.URL.Path != cluster.Path || r.Method != "GET" {
			t.Error("wrong discovery origin")
		}
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")) {
			t.Error("discovery not authenticated")
		}
		return &http.Response{StatusCode: int(status.Load()), ProtoMajor: 2, Body: io.NopCloser(strings.NewReader(body.Load().(string)))}, nil
	})
	if err := c.EnableBondDiscovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := c.discoveredBond(context.Background())
	if err != nil || first.Endpoints[0].Host != "a.example" {
		t.Fatal("missing initial snapshot", err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			got, err := c.discoveredBond(context.Background())
			if err != nil || got != first {
				t.Error("cache not shared", err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("unbounded cache requests", calls.Load())
	}
	// Refresh of unchanged topology preserves scheduler measurements.
	forceClusterRefresh(c, false)
	got, err := c.discoveredBond(context.Background())
	if err != nil || got != first {
		t.Fatal("unchanged topology reset scheduler", err)
	}
	// Topology replacement leaves old stream carriers untouched.
	body.Store(clusterBody("https://b.example"))
	forceClusterRefresh(c, false)
	second, err := c.discoveredBond(context.Background())
	if err != nil || second == first || second.Endpoints[0].Host != "b.example" || first.Endpoints[0].Host != "a.example" {
		t.Fatal("topology not isolated", err)
	}
	status.Store(503)
	forceClusterRefresh(c, false)
	if got, err := c.discoveredBond(context.Background()); err != nil || got != second {
		t.Fatal("transient failure lost valid snapshot", err)
	}
	forceClusterRefresh(c, true)
	if got, err := c.discoveredBond(context.Background()); err == nil || got != nil {
		t.Fatal("expired topology reused")
	}
	status.Store(200)
	forceClusterRefresh(c, false)
	if _, err := c.discoveredBond(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Authentication, redirects and malformed configurations never use stale data.
	for _, code := range []int{401, 302, 200} {
		status.Store(int64(code))
		if code == 200 {
			body.Store(`{"v":1,"nodes":[]}`)
		}
		forceClusterRefresh(c, false)
		if got, err := c.discoveredBond(context.Background()); err == nil || got != nil {
			t.Fatal("invalid response fell back to stale topology", code)
		}
	}
}

func TestClusterAuthorizationReloadAndProbeCover(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cluster.json")
	write := func(raw string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"v":1,"nodes":[{"url":"https://a.example","weight":4},{"url":"https://b.example","weight":1,"disabled":true}]}`)
	s := &Server{Username: "alice", Password: "secret", Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("credential leaked to public cover")
		}
		w.WriteHeader(418)
	})}
	if err := s.ConfigureCluster(file); err == nil {
		t.Fatal("relay-only discovery accepted")
	}
	hub := s.NewBondHub()
	defer hub.Close()
	s.Bond = hub
	if err := s.ConfigureCluster(file); err != nil {
		t.Fatal(err)
	}
	request := func(auth bool, proto int) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://main.example"+cluster.Path, nil)
		r.ProtoMajor = proto
		if auth {
			r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	if request(false, 2).Code != 418 || request(true, 1).Code != 418 {
		t.Fatal("discovery exposed outside auth/h2")
	}
	w := request(true, 2)
	var m cluster.Manifest
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &m) != nil || len(m.Nodes) != 1 || m.Nodes[0].Weight != 4 {
		t.Fatal("disabled node published")
	}
	id, _ := hub.Identity()
	if m.HubID != id || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing hub binding/cache policy")
	}
	write(`{"v":1,"nodes":[{"url":"https://b.example","weight":2}]}`)
	updated, err := cluster.DecodeManifest(request(true, 2).Body)
	if err != nil || updated.Nodes[0].URL != "https://b.example" || updated.HubID != id {
		t.Fatal("live configuration not loaded", err)
	}
	write(`{"v":1,"nodes":[]}`)
	if request(true, 2).Code != 503 {
		t.Fatal("invalid cluster file published")
	}
}
