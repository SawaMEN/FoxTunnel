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
	// Count data decisions independently in each direction: shared read/control
	// traffic must not consume every exploration slot of an upload-only path.
	direction := 0
	if op == opRead {
		direction = 1
	}
	sequence := c.adaptiveNext[direction]
	c.adaptiveNext[direction]++

	// Bond has at most eight trusted ingress endpoints. Keep selection on the
	// hot path allocation-free: a data block must not build candidate slices.
	// These two passes preserve the builtin tie, cooldown and exploration rules.
	earliestCooldown, readyFallback := -1, -1
	fastest := float64(0)
	for i := range tried {
		if tried[i] {
			continue
		}
		p := c.paths[i]
		if earliestCooldown < 0 || p.retryAt.Before(c.paths[earliestCooldown].retryAt) {
			earliestCooldown = i
		}
		if now.Before(p.retryAt) {
			continue
		}
		if readyFallback < 0 || p.pending < c.paths[readyFallback].pending {
			readyFallback = i
		}
		if rate, valid := adaptiveRate(p, op, now); valid && rate > fastest {
			fastest = rate
		}
	}
	if readyFallback < 0 {
		// Preserve recovery when all origins are in cooldown.
		return earliestCooldown
	}
	if bytes <= 0 {
		bytes = chunkSize
	}

	start := int(sequence % uint64(len(tried)))
	best, bestScore := -1, math.MaxFloat64
	unknown := -1
	for offset := range tried {
		i := (start + offset) % len(tried)
		if tried[i] || now.Before(c.paths[i].retryAt) {
			continue
		}
		p := c.paths[i]
		rate, measured := adaptiveRate(p, op, now)
		if !measured || rate <= 0 {
			// Rotate equal-backlog cold paths instead of pinning the first
			// endpoint. Track only the winning index rather than a slice.
			if unknown < 0 || p.pending < c.paths[unknown].pending {
				unknown = i
			}
			continue
		}
		// Very slow paths stay as fallbacks while a fast measured path has
		// headroom. In particular, a cooldown never defeats safe failover.
		if fastest > 0 && rate < 0.35*fastest {
			hasHeadroom := false
			for j := range tried {
				if tried[j] || now.Before(c.paths[j].retryAt) {
					continue
				}
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
		// ACKed goodput is not spare link capacity. Queue reservations only
		// estimate completion time; they do not change congestion control.
		score := latency + 1000*float64(p.inflightBytes+int64(bytes))/rate + 3*float64(p.pending)
		if c.RouteMode == "smart" && bondOrigin(c.Endpoints[i]) != c.DirectOrigin {
			score += 5
		}
		if score < bestScore {
			best, bestScore = i, score
		}
	}
	// Preserve the existing bounded fraction of real-data exploration.
	if unknown >= 0 && (best < 0 || sequence%adaptiveExploreEvery == 0) {
		return unknown
	}
	if best >= 0 {
		return best
	}
	// Every known path was rate-suppressed, or all were unmeasured.
	// Retain the lowest-backlog trusted fallback without blocking the stream.
	return readyFallback
}
