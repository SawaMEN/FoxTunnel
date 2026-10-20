package tunnel

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/cluster"
)

func TestBondTrafficConfigurationPropagation(t *testing.T) {
	c, err := NewClient("https://hub.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	relay, _ := url.Parse("https://relay.example")
	c.BondTraffic = "auto"
	c.BondAdaptive = true
	if err := c.SetFallbackServers([]*url.URL{relay}); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableBond(); err != nil {
		t.Fatal(err)
	}
	if c.bondClient == nil || c.bondClient.TrafficMode != "auto" {
		t.Fatal("ordinary bond dropped traffic policy")
	}
}

func TestDiscoveredBondTrafficConfigurationPropagation(t *testing.T) {
	const hubID = "abababababababababababababababababababababababababababababababab"
	c, err := NewClient("https://hub.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.BondTraffic = "latency"
	c.BondAdaptive = true
	c.transport = clusterTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Path != cluster.Path {
			t.Fatalf("unexpected request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, ProtoMajor: 2,
			Body: io.NopCloser(strings.NewReader(`{"v":1,"hub_id":"` + hubID +
				`","valid_for":120,"nodes":[{"url":"https://hub.example","weight":1},{"url":"https://relay.example","weight":1}]}`))}, nil
	})
	if err := c.EnableBondDiscovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := c.discoveredBond(context.Background())
	if err != nil || b == nil || b.TrafficMode != "latency" {
		t.Fatalf("discovery dropped traffic policy: %v %+v", err, b)
	}
}

func TestBondTrafficRejectsUnsafeConfigurations(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		adaptive bool
		valid    bool
	}{
		{"auto", true, true},
		{"throughput", false, false},
		{"latency", false, false},
		{"invalid", true, false},
		{"legacy", false, true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			if err := validateBondTraffic(tc.mode, tc.adaptive); (err == nil) != tc.valid {
				t.Fatalf("invalid traffic policy validation: %v", err)
			}
		})
	}
}
