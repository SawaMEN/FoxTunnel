package bond

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"
)

// Interleaved duplex work must not consume every exploration slot in one
// direction. Download activity says nothing about an unmeasured upload route.
func TestStableAdaptiveExplorationSurvivesDuplexInterleaving(t *testing.T) {
	for seed := uint64(0); seed < adaptiveExploreEvery; seed++ {
		c := adaptiveTestClient()
		now := time.Now()
		c.paths = []pathState{
			{uploadBps: 1e6, uploadSamples: 5, lastUpload: now, downloadBps: 1e6, downloadSamples: 5, lastDownload: now, latency: time.Millisecond},
			{downloadBps: 1e6, downloadSamples: 5, lastDownload: now, latency: time.Millisecond},
		}
		c.next = seed
		explored := false
		for range 2 * adaptiveExploreEvery {
			// Arrange that all old shared-counter multiples land on reads.
			if c.next%2 == 1 {
				_, done := c.reserveFor([]bool{false, false}, opRead, 0)
				done(time.Millisecond, false, 0)
			}
			index, done := c.reserveFor([]bool{false, false}, opWrite, chunkSize)
			explored = explored || index == 1
			done(time.Millisecond, false, 0)
			_, done = c.reserveFor([]bool{false, false}, opRead, 0)
			done(time.Millisecond, false, 0)
		}
		if !explored {
			t.Errorf("upload alternative starved at seed %d", seed)
		}
	}
}

func TestStableBondCombinations(t *testing.T) {
	for _, lanes := range []bool{false, true} {
		for _, depth := range []int{0, 4, 8} {
			for _, mode := range []string{"legacy", "adaptive", "auto", "latency", "throughput"} {
				t.Run(fmt.Sprintf("lanes=%t/pipeline=%d/%s", lanes, depth, mode), func(t *testing.T) {
					dial, dials := echoDial(t)
					c, _, _ := laneFixture(t, dial)
					c.PersistentLanes = lanes
					c.Pipeline = depth
					c.Adaptive = mode != "legacy"
					c.AutoTune = c.Adaptive && depth == 0
					if mode != "adaptive" {
						c.TrafficMode = mode
					}
					ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
					defer cancel()
					stream, err := c.Open(ctx, "example.org:443")
					if err != nil {
						t.Fatal(err)
					}
					defer stream.Close()
					// Unequal write sizes exercise coalescing, a partial last record,
					// and the transition between latency and throughput scheduling.
					payload := make([]byte, 512<<10+137)
					for i := range payload {
						payload[i] = byte(i*37 + i/251)
					}
					done := make(chan error, 1)
					go func() {
						sizes := []int{1, 137, 4095, 32768, 73}
						for off, step := 0, 0; off < len(payload); step++ {
							n := min(sizes[step%len(sizes)], len(payload)-off)
							if _, err := stream.Write(payload[off : off+n]); err != nil {
								done <- err
								return
							}
							off += n
						}
						done <- stream.CloseWrite()
					}()
					got, err := io.ReadAll(stream)
					writeErr := <-done
					if err != nil || writeErr != nil || !bytes.Equal(got, payload) {
						t.Fatalf("integrity: read=%v write=%v got=%d want=%d", err, writeErr, len(got), len(payload))
					}
					if dials.Load() != 1 {
						t.Fatalf("destination reopened: %d", dials.Load())
					}
					stream.Close()
					for _, m := range c.PathMetrics() {
						if m.PendingRequests != 0 || m.InFlightBytes != 0 {
							t.Fatalf("reservation retained: %+v", m)
						}
					}
				})
			}
		}
	}
}
