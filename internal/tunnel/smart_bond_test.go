package tunnel

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/SawaMEN/VetroffProxy/internal/cluster"
)

func TestSmartBondDiscoveryRequiresDirectHubAndRelay(t *testing.T) {
	const hubID = "abababababababababababababababababababababababababababababababab"
	for _, tc := range []struct {
		name  string
		nodes string
		valid bool
	}{
		{"only relay", `[{"url":"https://relay.example","weight":1}]`, false},
		{"only direct", `[{"url":"https://main.example","weight":1}]`, false},
		{"hub plus relay", `[{"url":"https://main.example:443","weight":1},{"url":"https://relay.example","weight":1}]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient("https://main.example", "alice", "secret", "")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.BondRoute = "smart"
			c.transport = clusterTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Path != cluster.Path {
					t.Fatalf("unexpected discovery request %s", r.URL)
				}
				return &http.Response{StatusCode: 200, ProtoMajor: 2, Body: io.NopCloser(strings.NewReader(
					`{"v":1,"hub_id":"` + hubID + `","valid_for":120,"nodes":` + tc.nodes + `}`))}, nil
			})
			err = c.EnableBondDiscovery(context.Background())
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected discovery result: %v", err)
			}
			if !tc.valid {
				return
			}
			bonded, err := c.discoveredBond(context.Background())
			if err != nil || bonded.RouteMode != "smart" || bonded.DirectOrigin != "main.example:443" || len(bonded.Endpoints) != 2 {
				t.Fatalf("smart route did not bind validated topology: %+v %v", bonded, err)
			}
		})
	}
}

func TestSmartBondRejectsExplicitFallbackConfiguration(t *testing.T) {
	c, err := NewClient("https://main.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.BondRoute = "smart"
	if err := c.SetFallbackServers([]string{"https://relay.example"}); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableBondDiscovery(context.Background()); err == nil {
		t.Fatal("ambiguous discovery with explicit fallback accepted")
	}
}
