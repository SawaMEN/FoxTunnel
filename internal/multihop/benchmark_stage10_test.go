package multihop

import (
	"fmt"
	"testing"
	"time"
)

// Fixed time and topology isolate scheduler CPU/allocations, not link capacity.
func BenchmarkStage10Selector(b *testing.B) {
	for _, count := range []int{2, 8, 16} {
		for _, scenario := range []string{"fresh", "cold", "cooldown"} {
			b.Run(fmt.Sprintf("%d/%s", count, scenario), func(b *testing.B) {
				now := time.Unix(1700000000, 0)
				candidates := make([]Candidate, count)
				for i := range candidates {
					candidates[i] = Candidate{ID: fmt.Sprint(i), Direct: i == 0,
						Quality: Measurement{Samples: 5, LatencyMS: float64(20 + i), LastSuccess: now}}
					if scenario == "cold" {
						candidates[i].Quality = Measurement{}
					}
					if scenario == "cooldown" {
						candidates[i].RetryAt = now.Add(time.Duration(i+1) * time.Second)
					}
				}
				state := State{}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var index int
					index, state = Select(candidates, state, now)
					if index < 0 {
						b.Fatal("no route")
					}
				}
			})
		}
	}
}
