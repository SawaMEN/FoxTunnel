package bond

import (
	"math"
	"time"
)

// trafficClass is local scheduler metadata, never a wire field. It only
// changes the choice of an already trusted ingress endpoint.
type trafficClass uint8

const (
	trafficUnspecified trafficClass = iota
	trafficLatency
	trafficThroughput
)

const trafficBulkThreshold = 128 << 10

// classifyTraffic uses only observable operation sizes and bytes already
// transferred by this stream. It does not inspect destinations or payloads.
// A short write remains latency-sensitive even in a long-lived connection.
func classifyTraffic(mode string, op byte, payloadBytes int, uploaded, downloaded uint64) trafficClass {
	switch mode {
	case "latency":
		return trafficLatency
	case "throughput":
		return trafficThroughput
	case "auto":
		if op == opWrite && payloadBytes < adaptiveMinBytes {
			return trafficLatency
		}
		if uploaded >= trafficBulkThreshold || downloaded >= trafficBulkThreshold {
			return trafficThroughput
		}
		return trafficLatency
	default:
		return trafficUnspecified
	}
}

// pickLatency prioritizes low full-exchange time and low queue depth for
// short-lived interactive data. It is not an ICMP RTT estimator. It preserves
// tried masks and cooldown failover, and learns unknown endpoints through a
// bounded fraction of real operations (no background probes).
// Called only under Client.mu.
func (c *Client) pickLatency(tried []bool, now time.Time) int {
	readyFallback, earliestCooldown := -1, -1
	known, unknown := false, -1
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
		if p.latency > 0 {
			known = true
		}
	}
	if readyFallback < 0 {
		return earliestCooldown
	}
	start := int(c.next % uint64(len(tried)))
	best, bestScore := -1, math.MaxFloat64
	for offset := range tried {
		i := (start + offset) % len(tried)
		if tried[i] || now.Before(c.paths[i].retryAt) {
			continue
		}
		p := c.paths[i]
		if p.latency <= 0 {
			if unknown < 0 || p.pending < c.paths[unknown].pending {
				unknown = i
			}
			continue
		}
		// Never ignore backlog: the lowest-latency ingress may be saturated.
		latencyMS := float64(p.latency) / float64(time.Millisecond)
		score := latencyMS*(1+0.25*float64(p.pending)) +
			2*float64(p.inflightBytes)/float64(chunkSize)
		if c.RouteMode == "smart" && bondOrigin(c.Endpoints[i]) != c.DirectOrigin {
			score += 5
		}
		if score < bestScore {
			best, bestScore = i, score
		}
	}
	if unknown >= 0 && (!known || c.next%adaptiveExploreEvery == 0) {
		return unknown
	}
	if best >= 0 {
		return best
	}
	return readyFallback
}
