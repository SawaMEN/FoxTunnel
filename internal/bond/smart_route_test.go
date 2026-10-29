package bond

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/multihop"
)

func TestSmartRoutePrefersMeasuredEndToEndRelay(t *testing.T) {
	hub, _ := url.Parse("https://HUB.example:443")
	relay, _ := url.Parse("https://relay.example")
	c := &Client{
		Endpoints: []*url.URL{hub, relay},
		RouteMode: "smart", DirectOrigin: "hub.example:443",
		ExpectedHub: strings.Repeat("ab", 32),
	}
	if got := bondOrigin(hub); got != "hub.example:443" {
		t.Fatal("origin canonicalization", got)
	}
	for i := 0; i < 5; i++ {
		pick, release := c.reserve([]bool{false, true})
		if pick != 0 {
			t.Fatalf("forced direct selected %d", pick)
		}
		release(80*time.Millisecond, false)
	}
	for i := 0; i < 5; i++ {
		pick, release := c.reserve([]bool{true, false})
		if pick != 1 {
			t.Fatalf("forced relay selected %d", pick)
		}
		release(18*time.Millisecond, false)
	}
	c.mu.Lock()
	c.routeState.Since = time.Now().Add(-time.Minute)
	c.routeState.Preferred = "hub.example:443"
	c.mu.Unlock()
	pick, release := c.reserve([]bool{false, false})
	if pick != 1 {
		t.Fatalf("faster full-path relay not selected: %d", pick)
	}
	release(18*time.Millisecond, false)
	c.mu.Lock()
	c.paths[1].retryAt = time.Now().Add(time.Minute)
	c.mu.Unlock()
	pick, release = c.reserve([]bool{false, false})
	if pick != 0 {
		t.Fatalf("failed relay not bypassed: %d", pick)
	}
	release(60*time.Millisecond, false)
}

func TestSmartRouteDropsStaleMeasurementsAfterNetworkChange(t *testing.T) {
	hub, _ := url.Parse("https://hub.example")
	relay, _ := url.Parse("https://relay.example")
	c := &Client{Endpoints: []*url.URL{hub, relay}, RouteMode: "smart", DirectOrigin: "hub.example:443"}
	pick, release := c.reserve([]bool{false, true})
	if pick != 0 {
		t.Fatal(pick)
	}
	release(30*time.Millisecond, false)
	c.ResetRouteQuality()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.routeMetrics[0].Samples != 0 || c.routeState.Preferred != "" || c.paths[0].latency != 0 {
		t.Fatalf("network-change route state kept: %+v %+v", c.routeMetrics[0], c.routeState)
	}
}

func TestSmartRouteNeedsPinnedHubAndDirectAndRelay(t *testing.T) {
	direct, _ := url.Parse("https://hub.example")
	relay, _ := url.Parse("https://relay.example")
	for _, tc := range []struct {
		name      string
		endpoints []*url.URL
		expected  string
		direct    string
	}{
		{"missing pin", []*url.URL{direct, relay}, "", "hub.example:443"},
		{"no direct", []*url.URL{relay, relay}, strings.Repeat("ab", 32), "hub.example:443"},
		{"no relay", []*url.URL{direct, direct}, strings.Repeat("ab", 32), "hub.example:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{Endpoints: tc.endpoints, ExpectedHub: tc.expected, DirectOrigin: tc.direct, RouteMode: "smart"}
			if stream, err := c.Open(t.Context(), "example.com:443"); err == nil || stream != nil {
				t.Fatal("unsafe smart route topology accepted")
			}
		})
	}
}

func TestRouteEstimatorIgnoresUnmeasuredReads(t *testing.T) {
	m := multihop.Update(multihop.Measurement{}, 25*time.Millisecond, false, time.Now())
	m = multihop.Update(m, 0, false, time.Now())
	if m.Samples != 1 || m.LatencyMS != 25 {
		t.Fatal(m)
	}
}
