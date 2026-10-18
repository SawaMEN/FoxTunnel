package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/bond"
	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

func TestBondedSOCKSGo(t *testing.T) { testBondedSOCKS(t, "go") }
func testBondedSOCKS(t *testing.T, backend string) {
	for _, depth := range []int{4, 8} {
		t.Run(strconv.Itoa(depth), func(t *testing.T) { testBondedSOCKSDepth(t, backend, depth) })
	}
}
func testBondedSOCKSDepth(t *testing.T, backend string, depth int) {
	testBondedSOCKSMode(t, backend, depth, false)
}

func TestDiscoveredBondedSOCKSGo(t *testing.T) { testBondedSOCKSMode(t, "go", 8, true) }

func testBondedSOCKSMode(t *testing.T, backend string, depth int, discover bool) {
	testBondedSOCKSNative(t, backend, depth, discover, "h2-connect")
}

func testBondedSOCKSNative(t *testing.T, backend string, depth int, discover bool, mode string) {
	var destinations atomic.Int64
	target := testDestination(t, func(c net.Conn) { destinations.Add(1); _, _ = io.Copy(c, c) })
	client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
	route := xhttp.Settings{}
	if xhttp.IsMode(mode) {
		route, _ = xhttp.Normalize("/cluster/shared-api", "cluster-route.example")
	}
	exit := &Server{Username: "alice", Password: "secret", AllowPrivate: true, XHTTPSettings: route}
	hub := exit.NewBondHub()
	defer hub.Close()
	exit.Bond = hub
	ready := make(chan struct{})
	// Publish all server settings before a handler can read them. QUIC's
	// goroutines must not race test-only late cluster initialization.
	hubServer := setupEndpoint(t, client, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-ready; exit.ServeHTTP(w, r) }))
	var calls [2]atomic.Int64
	var lost, lostOpen, failed atomic.Bool
	makeRelay := func(index int) *httptest.Server {
		relay, closeRelay, err := NewBondRelay(hubServer.URL, "alice", "secret", client.CACertFile)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(closeRelay)
		node := &Server{Username: "alice", Password: "secret", XHTTPSettings: route}
		node.Bond = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls[index].Add(1)
			if index == 0 && failed.Load() {
				<-r.Context().Done()
				return
			}
			data, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(data))
			if len(data) > 0 && data[0] == 0 && lostOpen.CompareAndSwap(false, true) {
				record := httptest.NewRecorder()
				relay.ServeHTTP(record, r)
				w.WriteHeader(504)
				return
			}
			// Deliver one write, discard its ACK, then retry it over the other node.
			if len(data) > 0 && data[0] == 1 && lost.CompareAndSwap(false, true) {
				record := httptest.NewRecorder()
				relay.ServeHTTP(record, r)
				w.WriteHeader(504)
				return
			}
			relay.ServeHTTP(w, r)
		})
		endpoint := setupEndpoint(t, client, node)
		if mode == "h3-post" {
			startNativeH3(t, endpoint, node)
		}
		return endpoint
	}
	a, b := makeRelay(0), makeRelay(1)
	usePrimary(t, client, a.URL)
	if err := client.SetFallbackServers([]string{b.URL}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTLSBackend(backend); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTransport(mode); err != nil {
		t.Fatal(err)
	}
	if xhttp.IsMode(mode) {
		if err := client.SetXHTTPSettings(route.Path, route.Host); err != nil {
			t.Fatal(err)
		}
	}
	client.FallbackAttemptTimeout = 250 * time.Millisecond
	client.BondPipeline = depth
	if discover {
		file := filepath.Join(t.TempDir(), "cluster.json")
		config, _ := json.Marshal(cluster.Config{Version: 1, Nodes: []cluster.Node{{URL: a.URL, Weight: 3, SNI: "example.com", PinSHA256: tlsidentity.Pin(a.Certificate())}, {URL: b.URL, Weight: 1, SNI: "example.com", PinSHA256: tlsidentity.Pin(b.Certificate())}}})
		if err := os.WriteFile(file, config, 0600); err != nil {
			t.Fatal(err)
		}
		if err := exit.ConfigureCluster(file); err != nil {
			t.Fatal(err)
		}
		usePrimary(t, client, hubServer.URL)
		if err := client.SetFallbackServers(nil); err != nil {
			t.Fatal(err)
		}
		if err := client.SetServerIdentity("example.com", tlsidentity.Pin(hubServer.Certificate())); err != nil {
			t.Fatal(err)
		}
		close(ready)
		if mode == "h3-post" {
			startNativeH3(t, hubServer, exit)
		}
		if err := client.EnableBondDiscovery(context.Background()); err != nil {
			t.Fatal(err)
		}
	} else {
		close(ready)
		if mode == "h3-post" {
			startNativeH3(t, hubServer, exit)
		}
		if err := client.EnableBond(); err != nil {
			t.Fatal(err)
		}
	}
	conn, code := connectSOCKS(t, addr, target)
	if code != 0 {
		t.Fatal(code)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	exchange := func(seed byte) {
		payload := make([]byte, 1<<20)
		state := uint64(seed) + 1
		for i := range payload {
			state = state*6364136223846793005 + 1
			payload[i] = byte(state >> 56)
		}
		done := make(chan error, 1)
		go func() { _, err := conn.Write(payload); done <- err }()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(payload, got) {
			t.Fatal("reordered or duplicated destination data")
		}
	}
	exchange(7)
	if !lostOpen.Load() {
		t.Fatal("lost open response was not exercised")
	}
	if !lost.Load() {
		t.Fatal("lost acknowledgement was not exercised")
	}
	if calls[0].Load() == 0 || calls[1].Load() == 0 {
		t.Fatal("did not use both nodes")
	}
	failed.Store(true)
	exchange(31) // The same destination socket survives a blackholed entry node.
	if destinations.Load() != 1 {
		t.Fatalf("destination redialed: %d", destinations.Load())
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	trailing, err := io.ReadAll(conn)
	if err != nil || len(trailing) != 0 {
		t.Fatalf("trailing duplicate data %d: %v", len(trailing), err)
	}
}

func TestBondAuthorizationAndConfiguration(t *testing.T) {
	var called atomic.Bool
	server := &Server{Username: "alice", Password: "secret", Bond: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Store(true) })}
	req := httptest.NewRequest(http.MethodPost, "https://example.org"+bond.Path, nil)
	req.ProtoMajor = 2
	result := httptest.NewRecorder()
	server.ServeHTTP(result, req)
	if called.Load() || result.Code != 404 {
		t.Fatal("unauthorized request reached hub")
	}
	c, err := NewClient("https://example.org", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.EnableBond() == nil {
		t.Fatal("single node accepted")
	}
	if err := c.SetFallbackServers([]string{"https://other.example"}); err != nil {
		t.Fatal(err)
	}
	c.Padding = true
	if c.EnableBond() == nil {
		t.Fatal("incompatible padding accepted")
	}
}

func BenchmarkBondedLoopback(b *testing.B) { benchmarkBondedPath(b, 0, 0) }

func BenchmarkBondedDelayedRPC(b *testing.B) {
	for _, mode := range []struct {
		name  string
		depth int
	}{{"4", 4}, {"8", 8}, {"auto", 0}} {
		b.Run(mode.name, func(b *testing.B) { benchmarkBondedPath(b, 40*time.Millisecond, mode.depth) })
	}
}

func benchmarkBondedPath(b *testing.B, delay time.Duration, pipeline int) {
	target := testDestination(b, func(c net.Conn) { _, _ = io.Copy(c, c) })
	client, addr := testClient(b, &Server{Username: "alice", Password: "secret"})
	exit := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
	hub := exit.NewBondHub()
	defer hub.Close()
	exit.Bond = hub
	hubServer := setupEndpoint(b, client, exit)
	nodes := make([]string, 0, 2)
	for range 2 {
		relay, closeRelay, err := NewBondRelay(hubServer.URL, "alice", "secret", client.CACertFile)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(closeRelay)
		var entry http.Handler = relay
		if delay > 0 {
			entry = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
					relay.ServeHTTP(w, r)
				case <-r.Context().Done():
				}
			})
		}
		node := setupEndpoint(b, client, &Server{Username: "alice", Password: "secret", Bond: entry})
		nodes = append(nodes, node.URL)
	}
	usePrimaryBenchmarkURL, err := url.Parse(nodes[0])
	if err != nil {
		b.Fatal(err)
	}
	client.ServerURL = usePrimaryBenchmarkURL
	if err := client.SetFallbackServers(nodes[1:]); err != nil {
		b.Fatal(err)
	}
	client.BondPipeline = pipeline
	if err := client.EnableBond(); err != nil {
		b.Fatal(err)
	}
	conn, code := connectSOCKS(b, addr, target)
	if code != 0 {
		b.Fatal(code)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte{17}, 1<<20)
	got := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
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
}
