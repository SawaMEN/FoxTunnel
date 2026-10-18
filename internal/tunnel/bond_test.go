package tunnel

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/bond"
)

func TestBondedSOCKSGo(t *testing.T) { testBondedSOCKS(t, "go") }
func testBondedSOCKS(t *testing.T, backend string) {
	var destinations atomic.Int64
	target := testDestination(t, func(c net.Conn) { destinations.Add(1); _, _ = io.Copy(c, c) })
	client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
	exit := &Server{Username: "alice", Password: "secret", AllowPrivate: true}
	hub := exit.NewBondHub()
	defer hub.Close()
	exit.Bond = hub
	hubServer := setupEndpoint(t, client, exit)
	var calls [2]atomic.Int64
	var lost, lostOpen, failed atomic.Bool
	makeRelay := func(index int) *httptest.Server {
		relay, closeRelay, err := NewBondRelay(hubServer.URL, "alice", "secret", client.CACertFile)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(closeRelay)
		node := &Server{Username: "alice", Password: "secret"}
		node.Bond = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls[index].Add(1)
			if index == 0 && failed.Load() {
				<-r.Context().Done()
				return
			}
			data, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(data))
			if index == 0 && len(data) > 0 && data[0] == 0 && lostOpen.CompareAndSwap(false, true) {
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
		return setupEndpoint(t, client, node)
	}
	a, b := makeRelay(0), makeRelay(1)
	usePrimary(t, client, a.URL)
	if err := client.SetFallbackServers([]string{b.URL}); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTLSBackend(backend); err != nil {
		t.Fatal(err)
	}
	client.FallbackAttemptTimeout = 250 * time.Millisecond
	if err := client.EnableBond(); err != nil {
		t.Fatal(err)
	}
	conn, code := connectSOCKS(t, addr, target)
	if code != 0 {
		t.Fatal(code)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	exchange := func(seed byte) {
		payload := bytes.Repeat([]byte{seed, seed + 1, seed + 2, seed + 3}, 256<<10)
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

func BenchmarkBondedLoopback(b *testing.B) {
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
		node := setupEndpoint(b, client, &Server{Username: "alice", Password: "secret", Bond: relay})
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
