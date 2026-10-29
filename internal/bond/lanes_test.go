package bond

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func laneFixture(t testing.TB, dial func(context.Context, string) (net.Conn, error)) (*Client, *atomic.Int64, *atomic.Int64) {
	t.Helper()
	hub := &Hub{Dial: dial}
	t.Cleanup(func() { hub.Close() })
	var requests, active atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		active.Add(1)
		defer active.Add(-1)
		hub.ServeHTTP(w, r)
	})
	endpoints := make([]*url.URL, 0, 2)
	var transport http.RoundTripper
	for range 2 {
		server := httptest.NewUnstartedServer(handler)
		server.EnableHTTP2 = true
		server.StartTLS()
		t.Cleanup(server.Close)
		u, _ := url.Parse(server.URL)
		endpoints = append(endpoints, u)
		if transport == nil {
			transport = server.Client().Transport
			t.Cleanup(server.Client().CloseIdleConnections)
		}
	}
	return &Client{Endpoints: endpoints, Transport: transport, Pipeline: 8, PersistentLanes: true}, &requests, &active
}
func echoDial(t testing.TB) (func(context.Context, string) (net.Conn, error), *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var dials atomic.Int64
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return func(ctx context.Context, _ string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}, &dials
}
func TestLanesCoalesceReuseAndHalfClose(t *testing.T) {
	dial, dials := echoDial(t)
	c, requests, _ := laneFixture(t, dial)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := c.Open(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.lanes == nil {
		t.Fatal("lane capability not negotiated")
	}
	payload := bytes.Repeat([]byte("abcdefgh"), 1<<18)
	done := make(chan error, 1)
	go func() {
		for p := payload; len(p) > 0; {
			n := min(len(p), 137)
			if _, err := s.Write(p[:n]); err != nil {
				done <- err
				return
			}
			p = p[n:]
		}
		done <- s.CloseWrite()
	}()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("stream reordered, duplicated, truncated")
	}
	if dials.Load() != 1 {
		t.Fatal("redialed destination")
	}
	if s.nextUp >= uint64(len(payload)/1024) {
		t.Fatal("small writes did not coalesce", s.nextUp)
	}
	if requests.Load() >= int64(s.nextUp) {
		t.Fatalf("channels were not reused: HTTP requests=%d upload records=%d", requests.Load(), s.nextUp)
	}
	s.lanes.mu.Lock()
	count := len(s.lanes.lanes)
	s.lanes.mu.Unlock()
	if count > 2*window {
		t.Fatal("unbounded lane pool", count)
	}
}
func TestLaneBackpressureCancellationJoinsWorkers(t *testing.T) {
	peerDone := make(chan struct{})
	c, _, active := laneFixture(t, func(context.Context, string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { <-peerDone; b.Close() }()
		return a, nil
	})
	defer close(peerDone)
	s, err := c.Open(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := s.Write(make([]byte, 32*chunkSize)); done <- err }()
	// Wait until the hub is blocked on the destination and all client slots fill.
	deadline := time.Now().Add(time.Second)
	for active.Load() < window && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("write exceeded bounded window without blocking")
	default:
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close retained workers")
	}
	if err := <-done; err == nil {
		t.Fatal("blocked Write did not observe cancellation")
	}
	deadline = time.Now().Add(time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 0 {
		t.Fatal("lane HTTP handlers leaked", active.Load())
	}
}
func TestLaneBindingFrameBoundsAndAdmission(t *testing.T) {
	dial, _ := echoDial(t)
	c, _, _ := laneFixture(t, dial)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, err := c.Open(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, test := range []struct {
		name       string
		size       uint32
		op         byte
		wrongToken bool
	}{
		{"undersized", headerSize - 1, opRead, false}, {"oversized", headerSize + chunkSize + 1, opRead, false}, {"open-on-lane", headerSize, opOpen, false}, {"other-session", headerSize, opRead, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := append([]byte(nil), s.token[:]...)
			var header [8]byte
			binary.BigEndian.PutUint32(header[:4], test.size)
			data = append(data, header[:]...)
			frame := make([]byte, headerSize)
			frame[0] = test.op
			copy(frame[1:33], s.token[:])
			if test.wrongToken {
				frame[1] ^= 1
			}
			data = append(data, frame...)
			req, _ := http.NewRequestWithContext(ctx, "POST", c.Endpoints[0].String()+Path, bytes.NewReader(data))
			req.Header.Set(LaneHeader, LaneVersion)
			req.Header.Set("X-Vetroff-Bond-Hub", s.hub)
			resp, err := c.Transport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			got, err := io.ReadAll(resp.Body)
			if err != nil || len(got) != 0 || resp.StatusCode != 200 {
				t.Fatalf("malformed record accepted: %d %x %v", resp.StatusCode, got, err)
			}
		})
	}
}

func TestLaneAdmissionLimit(t *testing.T) {
	dial, _ := echoDial(t)
	c, _, active := laneFixture(t, dial)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.Open(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var held []io.Closer
	defer func() {
		for _, closer := range held {
			closer.Close()
		}
	}()
	for i := 0; i <= 2*window; i++ {
		reader, writer := io.Pipe()
		held = append(held, writer)
		req, _ := http.NewRequestWithContext(ctx, "POST", c.Endpoints[0].String()+Path, reader)
		req.Header.Set(LaneHeader, LaneVersion)
		req.Header.Set("X-Vetroff-Bond-Hub", s.hub)
		go func() { _, _ = writer.Write(s.token[:]) }()
		resp, err := c.Transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, resp.Body)
		want := 200
		if i == 2*window {
			want = 429
		}
		if resp.StatusCode != want {
			t.Fatalf("lane %d: %d, want %d", i, resp.StatusCode, want)
		}
	}
	if active.Load() != 2*window {
		t.Fatal("unexpected active lane count", active.Load())
	}
}

func TestMixedLegacyRelayNegotiatesPerEntry(t *testing.T) {
	dial, _ := echoDial(t)
	c, _, _ := laneFixture(t, dial)
	base := c.Transport
	c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := base.RoundTrip(r)
		if err == nil && r.Header.Get(LaneHeader) == LaneVersion && r.URL.Host == c.Endpoints[0].Host {
			resp.Header.Del(LaneHeader)
		}
		return resp, err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.Open(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	payload := bytes.Repeat([]byte("mixed entries"), 1<<17)
	done := make(chan error, 1)
	go func() {
		_, err := s.Write(payload)
		if err == nil {
			err = s.CloseWrite()
		}
		done <- err
	}()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("builtin fallback corrupted stream")
	}
	s.lanes.mu.Lock()
	builtin := s.lanes.builtin[c.Endpoints[0].String()+Path]
	s.lanes.mu.Unlock()
	if !builtin {
		t.Fatal("builtin relay was not exercised")
	}
}

func TestSmallWriteFlushesWithoutHalfClose(t *testing.T) {
	dial, _ := echoDial(t)
	c, _, _ := laneFixture(t, dial)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s, err := c.Open(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Write([]byte("interactive")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 11)
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatal("timer did not flush interactive write", err)
	}
	if string(got) != "interactive" {
		t.Fatal("incorrect small write")
	}
}
