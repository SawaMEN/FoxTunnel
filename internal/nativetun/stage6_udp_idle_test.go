//go:build linux

package nativetun

import (
	"sync"
	"sync/atomic"
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

func TestStage6NativeUDPSlotsRejectExcessAndRecover(t *testing.T) {
	slots := make(chan struct{}, maxActiveUDP)
	releaseAll := make(chan struct{})
	var admitted atomic.Int64
	var entrants sync.WaitGroup
	var workers sync.WaitGroup
	for i := 0; i < 4*maxActiveUDP; i++ {
		entrants.Add(1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			ok := acquire(slots)
			if ok {
				admitted.Add(1)
			}
			entrants.Done()
			if ok {
				<-releaseAll
				release(slots)
			}
		}()
	}
	entrants.Wait()
	if got := admitted.Load(); got != maxActiveUDP {
		t.Fatalf("UDP admission admitted %d, expected %d", got, maxActiveUDP)
	}
	if len(slots) != maxActiveUDP || acquire(slots) {
		t.Fatal("overloaded native UDP admission bypassed its capacity")
	}
	close(releaseAll)
	workers.Wait()
	if len(slots) != 0 {
		t.Fatal("native UDP slot not released after shutdown")
	}
	if !acquire(slots) {
		t.Fatal("native UDP slots cannot be readmitted after saturation")
	}
	release(slots)
}
