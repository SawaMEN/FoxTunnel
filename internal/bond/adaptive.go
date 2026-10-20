package bond

import (
	"math"
	"time"
)

const (
	adaptiveMinBytes      = 4 << 10
	adaptiveMinSamples    = 3
	adaptiveSampleMaxAge  = 2 * time.Minute
	adaptiveExploreEvery  = 12
	adaptiveMaxSampleTime = 10 * time.Second
)

// BondPathMetric is a bounded, local-only per-ingress observation.
// Rates measure acknowledged application block bytes per elapsed HTTP
// operation, not spare network bandwidth or raw TCP/UDP link capacity.
type BondPathMetric struct {
	Origin            string    `json:"origin"`
	UploadBps         float64   `json:"upload_bytes_per_second"`
	DownloadBps       float64   `json:"download_bytes_per_second"`
	UploadSamples     uint64    `json:"upload_samples"`
	DownloadSamples   uint64    `json:"download_samples"`
	InFlightBytes     int64     `json:"in_flight_bytes"`
	PendingRequests   int       `json:"pending_requests"`
	ExchangeLatencyMS float64   `json:"exchange_latency_ms"`
	RetryAfter        time.Time `json:"retry_after,omitempty"`
}

func (c *Client) PathMetrics() []BondPathMetric {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]BondPathMetric, len(c.Endpoints))
	for i, endpoint := range c.Endpoints {
		entry := BondPathMetric{}
		if endpoint != nil {
			entry.Origin = endpoint.Scheme + "://" + endpoint.Host
		}
		if i < len(c.paths) {
			p := c.paths[i]
			entry.UploadBps = p.uploadBps
			entry.DownloadBps = p.downloadBps
			entry.UploadSamples = p.uploadSamples
			entry.DownloadSamples = p.downloadSamples
			entry.InFlightBytes = p.inflightBytes
			entry.PendingRequests = p.pending
			entry.ExchangeLatencyMS = float64(p.latency) / float64(time.Millisecond)
			entry.RetryAfter = p.retryAt
		}
		result[i] = entry
	}
	return result
}

// recordAdaptiveSample must hold c.mu. Only completed ACKed data operations
// are sampled: idle long-polls, cancellations and unverified responses cannot
// be interpreted as successful throughput measurements.
func (c *Client) recordAdaptiveSample(index int, op byte, bytes int, elapsed time.Duration, now time.Time) {
	if !c.Adaptive || bytes < adaptiveMinBytes || elapsed < time.Millisecond || elapsed > adaptiveMaxSampleTime {
		return
	}
	p := &c.paths[index]
	rate := float64(bytes) / elapsed.Seconds()
	if math.IsNaN(rate) || math.IsInf(rate, 0) || rate <= 0 {
		return
	}
	// Bound outliers from short loopback bursts, without treating them as
	// measured capacity in the path ranking.
	rate = math.Min(1e9, math.Max(1024, rate))
	switch op {
	case opWrite:
		if p.uploadSamples == 0 || now.Sub(p.lastUpload) > adaptiveSampleMaxAge {
			p.uploadBps = rate
			p.uploadSamples = 1
		} else {
			p.uploadBps += (rate - p.uploadBps) / 8
			p.uploadSamples++
		}
		p.lastUpload = now
	case opRead:
		if p.downloadSamples == 0 || now.Sub(p.lastDownload) > adaptiveSampleMaxAge {
			p.downloadBps = rate
			p.downloadSamples = 1
		} else {
			p.downloadBps += (rate - p.downloadBps) / 8
			p.downloadSamples++
		}
		p.lastDownload = now
	}
}

func adaptiveRate(p pathState, op byte, now time.Time) (float64, bool) {
	switch op {
	case opWrite:
		return p.uploadBps, p.uploadSamples >= adaptiveMinSamples && now.Sub(p.lastUpload) <= adaptiveSampleMaxAge
	case opRead:
		return p.downloadBps, p.downloadSamples >= adaptiveMinSamples && now.Sub(p.lastDownload) <= adaptiveSampleMaxAge
	default:
		return 0, false
	}
}

// pickAdaptive is called under c.mu, once for each attempt. It chooses among
// already trusted endpoints only and respects tried flags and retry cooldowns.
// Reservations account for work queued on each path, preventing fast paths
// from being overloaded while a slow ingress causes head-of-line stalls.
func (c *Client) pickAdaptive(tried []bool, op byte, bytes int, now time.Time) int {
	ready := make([]int, 0, len(tried))
	eligible := make([]int, 0, len(tried))
	for i := range tried {
		if tried[i] {
			continue
		}
		eligible = append(eligible, i)
		if !now.Before(c.paths[i].retryAt) {
			ready = append(ready, i)
		}
	}
	if len(eligible) == 0 {
		return -1
	}
	if len(ready) == 0 {
		// Preserve recovery when all origins are in cooldown.
		best := eligible[0]
		for _, i := range eligible[1:] {
			if c.paths[i].retryAt.Before(c.paths[best].retryAt) {
				best = i
			}
		}
		return best
	}

	if bytes <= 0 {
		bytes = chunkSize
	}
	start := int(c.next % uint64(len(tried)))
	best, bestScore := -1, math.MaxFloat64
	unknown := make([]int, 0, len(ready))
	fastest := float64(0)
	for _, i := range ready {
		if rate, valid := adaptiveRate(c.paths[i], op, now); valid && rate > fastest {
			fastest = rate
		}
	}
	for offset := range tried {
		i := (start + offset) % len(tried)
		if tried[i] || now.Before(c.paths[i].retryAt) {
			continue
		}
		p := c.paths[i]
		rate, measured := adaptiveRate(p, op, now)
		if !measured || rate <= 0 {
			unknown = append(unknown, i)
			continue
		}
		// A path dramatically slower than the fastest *available* ingress
		// cannot receive ordinary data while fast ingress still has headroom.
		// This is a soft exclusion: it does not defeat tried/cooldown failover.
		if fastest > 0 && rate < 0.35*fastest {
			hasHeadroom := false
			for _, j := range ready {
				otherRate, valid := adaptiveRate(c.paths[j], op, now)
				if valid && otherRate >= 0.8*fastest && c.paths[j].inflightBytes < 3*chunkSize {
					hasHeadroom = true
					break
				}
			}
			if hasHeadroom {
				continue
			}
		}
		latency := float64(p.latency) / float64(time.Millisecond)
		if latency <= 0 {
			latency = 60
		}
		// Approximate time to finish this queued block, not a claim of link
		// capacity. Request backlog penalizes paths already in use.
		score := latency + 1000*float64(p.inflightBytes+int64(bytes))/rate + 3*float64(p.pending)
		if c.RouteMode == "smart" && bondOrigin(c.Endpoints[i]) != c.DirectOrigin {
			score += 5
		}
		if score < bestScore {
			best, bestScore = i, score
		}
	}
	// A bounded fraction of REAL data operations explores under-sampled
	// paths to prevent permanent starvation after a temporary slowdown.
	if len(unknown) > 0 && (best < 0 || c.next%adaptiveExploreEvery == 0) {
		// Rotate ties during startup: an idle serial workload still gathers
		// measurements across all nodes rather than pinning the first origin.
		selected := -1
		for offset := range tried {
			i := (start + offset) % len(tried)
			for _, unknownIndex := range unknown {
				if unknownIndex != i {
					continue
				}
				if selected < 0 || c.paths[i].pending < c.paths[selected].pending {
					selected = i
				}
				break
			}
		}
		return selected
	}
	if best >= 0 {
		return best
	}
	// All known paths were suppressed by the rate guard, or are unmeasured.
	// Never block the session or skip trusted fallbacks.
	selected := ready[0]
	for _, i := range ready[1:] {
		if c.paths[i].pending < c.paths[selected].pending {
			selected = i
		}
	}
	return selected
}
