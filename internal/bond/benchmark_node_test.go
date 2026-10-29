package bond

import (
	"github.com/SawaMEN/VetroffProxy/internal/multihop"
	"net/url"
	"testing"
	"time"
)

// These allocation/CPU benchmarks isolate the decision overhead. They do
// NOT measure internet throughput, actual RTT, or justify a merge by themselves.
func BenchmarkBondPathSelection(b *testing.B) {
	for _, mode := range []struct {
		name     string
		adaptive bool
		smart    bool
	}{
		{"builtin", false, false}, {"adaptive", true, false},
		{"smart_adaptive", true, true},
	} {
		b.Run(mode.name, func(b *testing.B) {
			a, _ := url.Parse("https://hub.example")
			x, _ := url.Parse("https://relay.example")
			c := &Client{Endpoints: []*url.URL{a, x}, Adaptive: mode.adaptive}
			if mode.smart {
				c.RouteMode = "smart"
				c.DirectOrigin = "hub.example:443"
			}
			now := time.Now()
			c.paths = []pathState{
				{latency: 40 * time.Millisecond, uploadSamples: 5, uploadBps: 3e6, lastUpload: now},
				{latency: 70 * time.Millisecond, uploadSamples: 5, uploadBps: 2e6, lastUpload: now},
			}
			if mode.smart {
				c.routeMetrics = []multihop.Measurement{
					{Samples: 5, LatencyMS: 40, LastSuccess: now},
					{Samples: 5, LatencyMS: 70, LastSuccess: now},
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, finish := c.reserveFor([]bool{false, false}, opWrite, chunkSize)
				finish(40*time.Millisecond, false, chunkSize)
			}
		})
	}
}

// Deterministic synthetic latency matrix: without fake sleeps, benchmark
// only the path-selection CPU cost at low/high skew and queue pressure.
func BenchmarkBondSkewAndQueue(b *testing.B) {
	for _, tc := range []struct {
		name    string
		slow    float64
		backlog int64
	}{
		{"equal", 2e6, 0}, {"skew_10x", 2e5, 0}, {"backlogged", 2e6, 4 * chunkSize},
	} {
		b.Run(tc.name, func(b *testing.B) {
			a, _ := url.Parse("https://a.example")
			x, _ := url.Parse("https://b.example")
			c := &Client{Endpoints: []*url.URL{a, x}, Adaptive: true}
			now := time.Now()
			c.paths = []pathState{
				{latency: 40 * time.Millisecond, uploadBps: 2e6, uploadSamples: 5, lastUpload: now, inflightBytes: tc.backlog},
				{latency: 50 * time.Millisecond, uploadBps: tc.slow, uploadSamples: 5, lastUpload: now},
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, done := c.reserveFor([]bool{false, false}, opWrite, chunkSize)
				done(20*time.Millisecond, false, chunkSize)
			}
		})
	}
}
