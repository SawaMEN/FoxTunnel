package bond

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// Ordinary tests use two seconds; CI requests a longer held-session test.
func TestStableBondSustained(t *testing.T) {
	duration := 2 * time.Second
	if raw := os.Getenv("FOXTUNNEL_STABLE_SECONDS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 2 || n > 1800 {
			t.Fatal("invalid stable duration")
		}
		duration = time.Duration(n) * time.Second
	}
	for _, lanes := range []bool{false, true} {
		for _, mode := range []string{"auto", "latency", "throughput"} {
			t.Run(fmt.Sprintf("lanes=%t/%s", lanes, mode), func(t *testing.T) {
				t.Parallel()
				dial, dials := echoDial(t)
				h := &Hub{Dial: dial}
				defer h.Close()
				identity, err := h.Identity()
				if err != nil {
					t.Fatal(err)
				}
				var active atomic.Int64
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { active.Add(1); defer active.Add(-1); h.ServeHTTP(w, r) })
				c := &Client{PersistentLanes: lanes, Adaptive: true, AutoTune: true, TrafficMode: mode, ExpectedHub: identity, RouteMode: "smart"}
				for range 2 {
					server := httptest.NewUnstartedServer(handler)
					server.EnableHTTP2 = true
					server.StartTLS()
					defer server.Close()
					endpoint, _ := url.Parse(server.URL)
					c.Endpoints = append(c.Endpoints, endpoint)
					if c.Transport == nil {
						c.Transport = server.Client().Transport
						defer server.Client().CloseIdleConnections()
					}
				}
				c.DirectOrigin = bondOrigin(c.Endpoints[0])
				ctx, cancel := context.WithTimeout(t.Context(), duration+15*time.Second)
				defer cancel()
				stream, err := c.Open(ctx, "example.org:443")
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				start := time.Now()
				rounds := uint64(0)
				for time.Since(start) < duration {
					size := 64
					if rounds%2 == 0 {
						size = 32768
					}
					data := bytes.Repeat([]byte{byte(rounds)}, size)
					binary.BigEndian.PutUint64(data, rounds)
					if _, err := stream.Write(data); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, len(data))
					if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(data, got) {
						t.Fatalf("integrity round=%d: %v", rounds, err)
					}
					if rounds%17 == 0 {
						c.ResetRouteQuality()
					}
					rounds++
					time.Sleep(20 * time.Millisecond)
				}
				if err := stream.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if rest, err := io.ReadAll(stream); err != nil || len(rest) != 0 {
					t.Fatalf("half-close: trailing=%d err=%v", len(rest), err)
				}
				stream.Close()
				deadline := time.Now().Add(5 * time.Second)
				for active.Load() != 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if dials.Load() != 1 || active.Load() != 0 || rounds < 2 {
					t.Fatalf("lifecycle: dials=%d active=%d rounds=%d", dials.Load(), active.Load(), rounds)
				}
				for _, m := range c.PathMetrics() {
					if m.PendingRequests != 0 || m.InFlightBytes != 0 {
						t.Fatalf("reservation retained: %+v", m)
					}
				}
				t.Logf("held session duration=%s rounds=%d destination_dials=%d active_http=%d", time.Since(start), rounds, dials.Load(), active.Load())
			})
		}
	}
}
