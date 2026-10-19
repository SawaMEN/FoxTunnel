// Package multihop implements passive selection between a direct bond hub
// connection and trusted single-relay paths to the SAME authenticated hub.
package multihop

import (
	"math"
	"time"
)

const (
	MinSamples = 3
	MaxSampleAge = 2 * time.Minute
	MinDwell = 30 * time.Second
	ExploreEvery = 6
)

// Measurement is a per-ingress observation of complete bond operations.
// The elapsed duration includes the entire relay-to-hub leg, if any.
type Measurement struct {
	Samples uint64
	LatencyMS float64
	JitterMS float64
	FailurePct float64
	LastSuccess time.Time
}

type Candidate struct {
	ID string
	Direct bool
	Tried bool
	Active int
	RetryAt time.Time
	Quality Measurement
}

type State struct {
	Preferred string
	Since time.Time
	Decisions uint64
}

// Select never discovers or readdresses servers; callers supply a
// coordinator-validated topology. Unknown paths are explored only by real
// idempotent bond operations; stream payload is never replayed by this module.
func Select(candidates []Candidate, state State, now time.Time) (int, State) {
	state.Decisions++
	ready := make([]int, 0, len(candidates))
	pending := make([]int, 0, len(candidates))
	for i, c := range candidates {
		if c.Tried {
			continue
		}
		pending = append(pending, i)
		if !now.Before(c.RetryAt) {
			ready = append(ready, i)
		}
	}
	if len(pending) == 0 {
		return -1, state
	}
	if len(ready) == 0 {
		best := pending[0]
		for _, i := range pending[1:] {
			if candidates[i].RetryAt.Before(candidates[best].RetryAt) {
				best = i
			}
		}
		return best, state
	}

	unknown := make([]int, 0, len(ready))
	best := -1
	var bestScore float64
	held := -1
	var heldScore float64
	for _, i := range ready {
		c := candidates[i]
		if !fresh(c.Quality, now) {
			unknown = append(unknown, i)
			continue
		}
		score := c.Quality.LatencyMS + 1.5*c.Quality.JitterMS +
			4*c.Quality.FailurePct + 3*float64(max(0, c.Active))
		// A small complexity tax makes a relay win only if its measured
		// full end-to-end time is genuinely lower than direct hub access.
		if !c.Direct {
			score += 5
		}
		if best == -1 || score < bestScore {
			best, bestScore = i, score
		}
		if c.ID == state.Preferred {
			held, heldScore = i, score
		}
	}

	if best < 0 {
		return chooseUnknown(candidates, unknown, state.Decisions), state
	}
	selected := best
	if held >= 0 && held != best {
		improvement := math.Max(12, heldScore*0.20)
		if now.Sub(state.Since) < MinDwell || heldScore-bestScore < improvement {
			selected = held
		}
	}
	if state.Preferred != candidates[selected].ID {
		state.Preferred = candidates[selected].ID
		state.Since = now
	}
	if len(unknown) != 0 && state.Decisions%ExploreEvery == 0 {
		return chooseUnknown(candidates, unknown, state.Decisions), state
	}
	return selected, state
}

func fresh(m Measurement, now time.Time) bool {
	return m.Samples >= MinSamples && !m.LastSuccess.IsZero() &&
		!now.Before(m.LastSuccess) && now.Sub(m.LastSuccess) <= MaxSampleAge &&
		m.LatencyMS > 0 && !math.IsNaN(m.LatencyMS) &&
		!math.IsInf(m.LatencyMS, 0) &&
		m.JitterMS >= 0 && !math.IsNaN(m.JitterMS) &&
		!math.IsInf(m.JitterMS, 0) &&
		m.FailurePct >= 0 && m.FailurePct <= 100
}

func chooseUnknown(candidates []Candidate, unknown []int, decisions uint64) int {
	if len(unknown) == 0 {
		return -1
	}
	// A direct route is the conservative cold-start baseline. Every sixth
	// real operation can explore an unmeasured relay without probing.
	if decisions%ExploreEvery != 0 {
		for _, i := range unknown {
			if candidates[i].Direct {
				return i
			}
		}
	}
	start := int((decisions/ExploreEvery) % uint64(len(unknown)))
	best := unknown[start]
	for _, i := range unknown {
		if decisions%ExploreEvery == 0 && candidates[best].Direct && !candidates[i].Direct {
			best = i
			continue
		}
		if candidates[i].Direct == candidates[best].Direct &&
			candidates[i].Quality.Samples < candidates[best].Quality.Samples {
			best = i
		}
	}
	return best
}

// Update tracks an EWMA of complete non-long-poll operations. Callers are
// responsible for excluding idle reads and unsuccessful HTTP replies.
func Update(m Measurement, elapsed time.Duration, failed bool, now time.Time) Measurement {
	if failed {
		// Clamp a bounded moving estimate; failed requests must not invent RTT.
		m.FailurePct += (100-m.FailurePct)/8
		return m
	}
	if elapsed <= 0 {
		return m
	}
	ms := float64(elapsed)/float64(time.Millisecond)
	if m.Samples == 0 {
		m.LatencyMS = ms
	} else {
		delta := math.Abs(ms-m.LatencyMS)
		m.JitterMS += (delta-m.JitterMS)/8
		m.LatencyMS += (ms-m.LatencyMS)/8
	}
	m.FailurePct *= 7.0/8.0
	m.Samples++
	m.LastSuccess = now
	return m
}
