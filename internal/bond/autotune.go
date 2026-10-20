package bond

import "time"

// AutoTunePolicy adjusts only the existing bounded 4/8 record pipeline.
// The observed goodput is application ACK throughput, not physical capacity.
// No timer, probe, wire change, new retry, or extra memory quota is introduced.
type AutoTunePolicy struct {
	Enabled bool
}

// pipelineTargetLocked is called while Client.mu is held. A measured BDP
// smaller than four records favors latency and low memory. At least three
// fresh successful data operations are required before trying eight slots.
// Existing in-flight slots are never revoked.
func (c *Client) pipelineTargetLocked(now time.Time) int {
	if !c.AutoTune || !c.Adaptive {
		return 0 // delegate to legacy pipelineDepth
	}
	const block = 32 << 10
	ready := 0
	var aggregate float64
	for _, p := range c.paths {
		if now.Before(p.retryAt) {
			continue
		}
		rate, known := adaptiveRate(p, opWrite, now)
		if !known || rate <= 0 || p.latency <= 0 || p.pending > 5 {
			continue
		}
		// Clamp the latency term. Full operation time can include server
		// processing, so avoid multiplying enormous outliers.
		latency := min(p.latency, 500*time.Millisecond)
		aggregate += rate * latency.Seconds()
		ready++
	}
	if ready == 0 {
		return 4 // no fabricated bandwidth estimate during cold start
	}
	// A margin above four blocks avoids increasing concurrency for only
	// borderline BDP estimates that may regress short interactive traffic.
	if aggregate >= 5*block {
		return 8
	}
	return 4
}
