package bond

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func trafficTestClient(mode string) *Client {
	a, _ := url.Parse("https://low-latency.example")
	b, _ := url.Parse("https://high-throughput.example")
	now := time.Now()
	return &Client{
		Endpoints: []*url.URL{a, b}, Adaptive: true, TrafficMode: mode,
		paths: []pathState{
			{latency: 10 * time.Millisecond, uploadBps: 40_000, uploadSamples: 6, lastUpload: now},
			{latency: 65 * time.Millisecond, uploadBps: 4_000_000, uploadSamples: 6, lastUpload: now},
		},
	}
}

func TestTrafficClassAutoTransition(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		op       byte
		size     int
		up, down uint64
		want     trafficClass
	}{
		{"builtin small", "builtin", opWrite, 128, 0, 0, trafficUnspecified},
		{"latency always", "latency", opRead, 0, 10 * trafficBulkThreshold, 0, trafficLatency},
		{"throughput always", "throughput", opWrite, 128, 0, 0, trafficThroughput},
		{"auto cold download", "auto", opRead, 0, 0, 0, trafficLatency},
		{"auto short upload", "auto", opWrite, 150, trafficBulkThreshold, 0, trafficLatency},
		{"auto big upload", "auto", opWrite, chunkSize, trafficBulkThreshold, 0, trafficThroughput},
		{"auto big download", "auto", opRead, 0, 0, trafficBulkThreshold, trafficThroughput},
		{"auto early block", "auto", opWrite, chunkSize, chunkSize, 0, trafficLatency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyTraffic(tc.mode, tc.op, tc.size, tc.up, tc.down); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTrafficLatencyAndThroughputChooseDifferentIngress(t *testing.T) {
	latency := trafficTestClient("latency")
	pick, done := latency.reserveForClass([]bool{false, false}, opWrite, chunkSize, trafficLatency)
	if pick != 0 {
		t.Fatalf("low-latency operation selected path %d", pick)
	}
	done(10*time.Millisecond, false, 0)

	bulk := trafficTestClient("throughput")
	pick, done = bulk.reserveForClass([]bool{false, false}, opWrite, chunkSize, trafficThroughput)
	if pick != 1 {
		t.Fatalf("bulk operation ignored higher ACKed goodput: %d", pick)
	}
	done(65*time.Millisecond, false, 0)
}

func TestTrafficLatencyBacklogAndFailover(t *testing.T) {
	c := trafficTestClient("latency")
	c.paths[0].pending = 20
	c.paths[0].inflightBytes = 7 * chunkSize
	c.paths[1].latency = 25 * time.Millisecond
	pick, done := c.reserveForClass([]bool{false, false}, opRead, 0, trafficLatency)
	if pick != 1 {
		t.Fatalf("latency mode sent work to saturated ingress: %d", pick)
	}
	done(0, false, 0)
	c.paths[1].retryAt = time.Now().Add(time.Minute)
	pick, done = c.reserveForClass([]bool{false, false}, opWrite, 128, trafficLatency)
	if pick != 0 {
		t.Fatalf("latency mode ignored cooldown: %d", pick)
	}
	done(0, false, 0)
	c.paths[0].retryAt = time.Now().Add(30 * time.Second)
	pick, done = c.reserveForClass([]bool{false, false}, opWrite, 128, trafficLatency)
	if pick != 0 {
		t.Fatalf("both cooling: must retry earliest cooldown: %d", pick)
	}
	done(0, false, 0)
	pick, done = c.reserveForClass([]bool{true, false}, opWrite, 128, trafficLatency)
	if pick != 1 {
		t.Fatalf("tried mask was bypassed: %d", pick)
	}
	done(0, false, 0)
}

func TestTrafficLatencyUnknownPathsExploreWithoutProbes(t *testing.T) {
	c := trafficTestClient("latency")
	c.paths[1].latency = 0
	c.next = adaptiveExploreEvery - 1
	pick, done := c.reserveForClass([]bool{false, false}, opWrite, 128, trafficLatency)
	if pick != 1 {
		t.Fatalf("unknown ready path cannot be sampled by real traffic: %d", pick)
	}
	done(20*time.Millisecond, false, 0)
	c.ResetRouteQuality()
	for _, m := range c.PathMetrics() {
		if m.ExchangeLatencyMS != 0 {
			t.Fatalf("network reset retained stale latency: %+v", m)
		}
	}
}

func TestTrafficModeValidation(t *testing.T) {
	for _, tc := range []struct {
		mode      string
		adaptive  bool
		validMode bool
	}{
		{"", false, true},
		{"builtin", false, true},
		{"auto", false, false},
		{"throughput", false, false},
		{"latency", true, true},
		{"auto", true, true},
		{"throughput", true, true},
		{"unsafe", true, false},
	} {
		c := trafficTestClient(tc.mode)
		c.Adaptive = tc.adaptive
		c.Transport = roundTripFunc(func(_ *http.Request) (*http.Response, error) { return nil, io.EOF })
		_, err := c.Open(t.Context(), "example.org:443")
		// A valid mode proceeds to network setup and fails there; an
		// invalid one must fail at input validation before network setup.
		if !tc.validMode && err == nil {
			t.Fatalf("invalid traffic mode %q accepted", tc.mode)
		}
		if tc.validMode && (err == nil || err.Error() == "unknown bond traffic mode" || err.Error() == "bond traffic mode requires adaptive scheduling") {
			t.Fatalf("valid mode %q rejected early: %v", tc.mode, err)
		}
	}
}

func TestTrafficModesPreserveHTTP2StreamIntegrity(t *testing.T) {
	for _, mode := range []string{"auto", "latency", "throughput"} {
		t.Run(mode, func(t *testing.T) {
			dial, dials := echoDial(t)
			c, _, _ := laneFixture(t, dial)
			c.PersistentLanes = false
			c.Pipeline = 4
			c.Adaptive = true
			c.TrafficMode = mode
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s, err := c.Open(ctx, "example.org:443")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			data := bytes.Repeat([]byte("interactive-and-bulk-"), 18000)
			done := make(chan error, 1)
			go func() {
				_, err := s.Write(data)
				if err == nil {
					err = s.CloseWrite()
				}
				done <- err
			}()
			got, readErr := io.ReadAll(s)
			writeErr := <-done
			if readErr != nil || writeErr != nil {
				t.Fatalf("transfer error: read=%v write=%v", readErr, writeErr)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("invalid byte stream: read %d, expected %d", len(got), len(data))
			}
			if dials.Load() != 1 {
				t.Fatalf("unexpected destination redials: %d", dials.Load())
			}
		})
	}
}
