//go:build linux

package nativetun

import (
	"testing"
	"time"
)

func TestStage6UDPIdleDNSDoesNotExhaustNativeSlots(t *testing.T) {
	if udpDNSIdle >= udpIdle {
		t.Fatal("ephemeral DNS associations must expire before ordinary UDP mappings")
	}
	if got := udpFlowIdleFor(53); got != 3*time.Second {
		t.Fatalf("DNS UDP idle window changed: %s", got)
	}
	for _, port := range []uint16{1, 80, 123, 443, 853, 5656, 65535} {
		if got := udpFlowIdleFor(port); got != udpIdle {
			t.Fatalf("non-DNS UDP port %d mapping expired after %s, expected %s", port, got, udpIdle)
		}
	}
	if udpDNSIdle < time.Second {
		t.Fatal("DNS idle budget must permit a delayed local response")
	}
}
