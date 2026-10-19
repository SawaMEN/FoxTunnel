package nodeperf

import (
	"math"
	"time"
)

// Candidate is a trusted, explicitly configured HTTPS origin. Select never
// adds endpoints or changes identity verification and authorization policy.
type Candidate struct {
	Origin  string
	Active  int
	RetryAt time.Time
	Tried   bool
}

// SelectionState is guarded by the caller's endpoint scheduler lock.
// Preferred is deliberately separate from the failover-mode preferred index.
type SelectionState struct {
	Preferred string
	Since     time.Time
	Decisions uint64
}

const (
	minSuccessfulSamples = 3
	qualityMaxAge        = 2 * time.Minute
	minimumDwell         = 30 * time.Second
	explorationPeriod    = 6
)

type scoredNode struct {
	index int
	score float64
}

// Select chooses a NEW stream's ingress only. It never moves an existing
// stream, retries application bytes, or sends background probes.
// Every sixth decision can explore an under-sampled trusted origin.
// Established preference changes only for a >=20% and >=12ms improvement
// after 30 seconds, or immediately when the preferred route is unavailable.
func Select(candidates []Candidate, measurements []Snapshot, state SelectionState, now time.Time) (int, SelectionState) {
	available := make([]int, 0, len(candidates))
	for i, n := range candidates {
		if !n.Tried {
			available = append(available, i)
		}
	}
	if len(available) == 0 {
		return -1, state
	}
	state.Decisions++
	ready := make([]int, 0, len(available))
	for _, i := range available {
		if !now.Before(candidates[i].RetryAt) {
			ready = append(ready, i)
		}
	}
	// Keep the existing fail-open behavior when EVERY configured node is in
	// transient cooldown: attempt one, never wait for a scheduled probe.
	if len(ready) == 0 {
		chosen := available[0]
		for _, i := range available[1:] {
			if candidates[i].RetryAt.Before(candidates[chosen].RetryAt) ||
				(candidates[i].RetryAt.Equal(candidates[chosen].RetryAt) && candidates[i].Active < candidates[chosen].Active) {
				chosen = i
			}
		}
		return chosen, state
	}

	byOrigin := make(map[string]Snapshot, len(measurements))
	for _, measurement := range measurements {
		byOrigin[measurement.Origin] = measurement
	}
	known := make([]scoredNode, 0, len(ready))
	unknown := make([]int, 0, len(ready))
	var preferred *scoredNode
	for _, i := range ready {
		node := candidates[i]
		metric := byOrigin[node.Origin]
		if !usableQuality(metric, now) {
			unknown = append(unknown, i)
			continue
		}
		score := metric.RequestLatencyMS + 1.5*metric.JitterMS + 4*metric.RecentFailurePct + 3*float64(max(0, node.Active))
		entry := scoredNode{index: i, score: score}
		known = append(known, entry)
		if node.Origin == state.Preferred {
			copy := entry
			preferred = &copy
		}
	}

	if len(known) == 0 {
		// Cold start: spread REAL streams across the pool, with no extra probes.
		// Counted failures raise sampling cost so a dead origin cannot
		// monopolize warm-up while ready alternatives exist.
		return chooseUnknown(candidates, byOrigin, unknown, state.Decisions), state
	}
	best := known[0]
	for _, node := range known[1:] {
		if node.score < best.score {
			best = node
		}
	}
	chosen := best
	if preferred != nil && preferred.index != best.index {
		margin := math.Max(12, preferred.score*0.20)
		if now.Sub(state.Since) < minimumDwell || preferred.score-best.score < margin {
			chosen = *preferred
		}
	}
	if state.Preferred != candidates[chosen.index].Origin {
		state.Preferred = candidates[chosen.index].Origin
		state.Since = now
	}
	if len(unknown) > 0 && state.Decisions%explorationPeriod == 0 {
		// Exploration must not replace the stable preferred node. A failed
		// exploratory attempt follows the existing bounded fallback rules.
		return chooseUnknown(candidates, byOrigin, unknown, state.Decisions), state
	}
	return chosen.index, state
}

func usableQuality(s Snapshot, now time.Time) bool {
	return s.SuccessfulResponses >= minSuccessfulSamples &&
		!s.LastSuccess.IsZero() && !now.Before(s.LastSuccess) &&
		now.Sub(s.LastSuccess) <= qualityMaxAge &&
		s.RequestLatencyMS > 0 && !math.IsNaN(s.RequestLatencyMS) &&
		!math.IsInf(s.RequestLatencyMS, 0) &&
		!math.IsNaN(s.JitterMS) && !math.IsInf(s.JitterMS, 0) &&
		s.JitterMS >= 0 && s.RecentFailurePct >= 0 && s.RecentFailurePct <= 100
}

func chooseUnknown(candidates []Candidate, quality map[string]Snapshot, indices []int, counter uint64) int {
	if len(indices) == 0 {
		return -1
	}
	start := int((counter - 1) % uint64(len(indices)))
	chosen := indices[start]
	weight := func(i int) float64 {
		measure := quality[candidates[i].Origin]
		// Prefer less-sampled origins, but avoid hammering an origin with
		// repeated failures. Active streams provide a tie-break/penalty.
		return float64(measure.Samples) + 0.10*measure.RecentFailurePct +
			float64(max(0, candidates[i].Active))
	}
	bestWeight := weight(chosen)
	for offset := 1; offset < len(indices); offset++ {
		i := indices[(start+offset)%len(indices)]
		if value := weight(i); value < bestWeight {
			chosen, bestWeight = i, value
		}
	}
	return chosen
}
