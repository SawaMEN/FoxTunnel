package tunnel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestProtocolPolicyBondFailsBeforeRequests(t *testing.T) {
	for _, discovery := range []bool{false, true} {
		c, err := NewClient("https://node.invalid", "alice", "secret", "")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		requests := 0
		c.transport = probeRoundTripper(func(*http.Request) (*http.Response, error) {
			requests++
			return nil, errors.New("unexpected request")
		})
		if !discovery {
			if err := c.SetFallbackServers([]string{"https://second.invalid"}); err != nil {
				t.Fatal(err)
			}
		}
		c.RequireProtocolNegotiation = true
		if discovery {
			err = c.EnableBondDiscovery(context.Background())
		} else {
			err = c.EnableBond()
		}
		c.Close()
		if err == nil || !strings.Contains(err.Error(), "strict protocol policy") || requests != 0 || c.bondClient != nil || c.bondDiscovery != nil {
			t.Fatal("strict bond/discovery made an unnegotiated request", err)
		}
	}
}
