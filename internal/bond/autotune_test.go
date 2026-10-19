package bond

import (
	"net/url"
	"testing"
	"time"
)

func TestAutoTuneColdStartAndMeasuredBDP(t *testing.T) {
	u, _ := url.Parse("https://a.example")
	c := &Client{Endpoints: []*url.URL{u}, Adaptive: true, AutoTune: true}
	if got := c.pipelineDepth(); got != 4 { t.Fatalf("cold start=%d", got) }
	now := time.Now()
	c.mu.Lock()
	c.paths = []pathState{{uploadBps: 2_000_000, uploadSamples: 5,
		lastUpload: now, latency: 120 * time.Millisecond}}
	c.mu.Unlock()
	if got := c.pipelineDepth(); got != 8 { t.Fatalf("high BDP=%d", got) }
	c.mu.Lock()
	c.paths[0].uploadBps = 120_000
	c.mu.Unlock()
	if got := c.pipelineDepth(); got != 4 { t.Fatalf("low BDP=%d", got) }
	c.mu.Lock()
	c.paths[0].uploadBps = 2_000_000
	c.paths[0].lastUpload = now.Add(-3*time.Minute)
	c.mu.Unlock()
	if got := c.pipelineDepth(); got != 4 { t.Fatalf("stale samples=%d", got) }
}

func TestAutoTuneOverridesAndValidation(t *testing.T) {
	u, _ := url.Parse("https://a.example")
	c := &Client{Endpoints: []*url.URL{u}, Adaptive: true, AutoTune: true, Pipeline: 4}
	if got := c.pipelineDepth(); got != 4 { t.Fatal(got) }
	c.Pipeline = 8
	if got := c.pipelineDepth(); got != 8 { t.Fatal(got) }
	c.Adaptive = false
	if _, err := c.Open(t.Context(),"example.com:443"); err == nil {
		t.Fatal("autotune without adaptive accepted")
	}
}

func TestAutoTuneBoundedAndNetworkReset(t *testing.T) {
	c := adaptiveTestClient()
	c.AutoTune = true
	c.paths = make([]pathState,2)
	now := time.Now()
	for i := range c.paths {
		c.paths[i] = pathState{uploadBps: 10_000_000, uploadSamples: 4, lastUpload: now,
			latency: 250*time.Millisecond}
	}
	if got := c.pipelineDepth(); got != 8 { t.Fatal(got) }
	c.ResetRouteQuality()
	if got := c.pipelineDepth(); got != 4 { t.Fatalf("network reset should relearn: %d",got) }
}
