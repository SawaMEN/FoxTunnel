// Package nodeperf records bounded, passive per-origin carrier measurements.
// Request latency and failed requests are not ICMP RTT or packet loss.
package nodeperf

import (
	"sort"
	"sync"
	"time"
)

const maxOrigins = 32
const recentWindow = 32

// Snapshot contains only node origin and aggregate transport measurements.
// Payload addresses, credentials and request paths are intentionally omitted.
type Snapshot struct {
	Origin              string    `json:"origin"`
	Samples             uint64    `json:"samples"`
	FailedRequests      uint64    `json:"failed_requests"`
	SuccessfulResponses uint64    `json:"successful_responses"`
	LastSuccess         time.Time `json:"last_success"`
	RecentFailurePct    float64   `json:"recent_failure_pct"`
	RequestLatencyMS    float64   `json:"request_latency_ms"`
	JitterMS            float64   `json:"jitter_ms"`
	ActiveRequests      int       `json:"active_requests"`
	UploadedBytes       uint64    `json:"uploaded_bytes"`
	DownloadedBytes     uint64    `json:"downloaded_bytes"`
	UploadBps           float64   `json:"upload_bps"`
	DownloadBps         float64   `json:"download_bps"`
	LastObserved        time.Time `json:"last_observed"`
}

type node struct {
	snapshot                                 Snapshot
	failures                                 [recentWindow]bool
	recentIndex, recentCount, recentFailures int
	hasLatency                               bool
	previousMS                               float64
	trafficFrom                              time.Time
	windowUpload, windowDownload             uint64
	lastTransfer                             time.Time
}

// Monitor is safe for concurrent transports, including streaming HTTP bodies.
type Monitor struct {
	mu    sync.Mutex
	nodes map[string]*node
}

func New() *Monitor { return &Monitor{nodes: make(map[string]*node)} }

func (m *Monitor) entry(origin string, now time.Time) *node {
	if origin == "" {
		return nil
	}
	if n := m.nodes[origin]; n != nil {
		return n
	}
	if len(m.nodes) >= maxOrigins {
		var oldest string
		var stamp time.Time
		for key, n := range m.nodes {
			if n.snapshot.ActiveRequests > 0 {
				continue
			}
			if oldest == "" || n.snapshot.LastObserved.Before(stamp) {
				oldest, stamp = key, n.snapshot.LastObserved
			}
		}
		if oldest == "" {
			return nil
		}
		delete(m.nodes, oldest)
	}
	n := &node{snapshot: Snapshot{Origin: origin, LastObserved: now}}
	m.nodes[origin] = n
	return n
}

// Begin registers an in-flight HTTP request. Every call must have one End.
func (m *Monitor) Begin(origin string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n := m.entry(origin, time.Now()); n != nil {
		n.snapshot.ActiveRequests++
		n.snapshot.LastObserved = time.Now()
	}
}

func (m *Monitor) End(origin string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n := m.nodes[origin]; n != nil && n.snapshot.ActiveRequests > 0 {
		n.snapshot.ActiveRequests--
	}
}

// Observe measures time to response headers (or request failure). A failed
// request is a transport failure or a non-2xx/3xx HTTP status, NOT lost packets.
func (m *Monitor) Observe(origin string, elapsed time.Duration, statusCode int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	n := m.entry(origin, now)
	if n == nil {
		return
	}
	n.snapshot.LastObserved = now
	n.snapshot.Samples++
	failed := err != nil || statusCode < 200 || statusCode >= 400
	if n.recentCount == recentWindow && n.failures[n.recentIndex] {
		n.recentFailures--
	}
	n.failures[n.recentIndex] = failed
	if failed {
		n.recentFailures++
		n.snapshot.FailedRequests++
	}
	n.recentIndex = (n.recentIndex + 1) % recentWindow
	if n.recentCount < recentWindow {
		n.recentCount++
	}
	n.snapshot.RecentFailurePct = 100 * float64(n.recentFailures) / float64(n.recentCount)
	if failed {
		return
	}
	n.snapshot.SuccessfulResponses++
	n.snapshot.LastSuccess = now
	sampleMS := float64(elapsed) / float64(time.Millisecond)
	if sampleMS < 0 {
		return
	}
	if !n.hasLatency {
		n.snapshot.RequestLatencyMS = sampleMS
		n.hasLatency = true
	} else {
		difference := sampleMS - n.previousMS
		if difference < 0 {
			difference = -difference
		}
		n.snapshot.JitterMS += (difference - n.snapshot.JitterMS) / 8
		n.snapshot.RequestLatencyMS += (sampleMS - n.snapshot.RequestLatencyMS) / 8
	}
	n.previousMS = sampleMS
}

// Transfer counts carrier HTTP body bytes as read by transports/applications.
// These are not independently measured link capacity or pure user goodput.
func (m *Monitor) Transfer(origin string, uploaded, downloaded int) {
	if uploaded <= 0 && downloaded <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	n := m.entry(origin, now)
	if n == nil {
		return
	}
	if n.trafficFrom.IsZero() || now.Sub(n.trafficFrom) >= 10*time.Second {
		n.trafficFrom = now
		n.windowUpload = 0
		n.windowDownload = 0
	}
	if uploaded > 0 {
		n.snapshot.UploadedBytes += uint64(uploaded)
		n.windowUpload += uint64(uploaded)
	}
	if downloaded > 0 {
		n.snapshot.DownloadedBytes += uint64(downloaded)
		n.windowDownload += uint64(downloaded)
	}
	n.lastTransfer = now
	n.snapshot.LastObserved = now
}

// InvalidateQuality discards route-quality history after an OS network change
// while preserving in-flight accounting and cumulative traffic counters.
func (m *Monitor) InvalidateQuality() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.nodes {
		n.snapshot.Samples = 0
		n.snapshot.SuccessfulResponses = 0
		n.snapshot.FailedRequests = 0
		n.snapshot.RecentFailurePct = 0
		n.snapshot.RequestLatencyMS = 0
		n.snapshot.JitterMS = 0
		n.snapshot.LastSuccess = time.Time{}
		n.failures = [recentWindow]bool{}
		n.recentIndex, n.recentCount, n.recentFailures = 0, 0, 0
		n.hasLatency = false
		n.previousMS = 0
		n.trafficFrom, n.lastTransfer = time.Time{}, time.Time{}
		n.windowUpload, n.windowDownload = 0, 0
	}
}

func (m *Monitor) Snapshot() []Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	out := make([]Snapshot, 0, len(m.nodes))
	for _, n := range m.nodes {
		item := n.snapshot
		if !n.trafficFrom.IsZero() && now.Sub(n.lastTransfer) <= 20*time.Second {
			elapsed := now.Sub(n.trafficFrom).Seconds()
			if elapsed < 1 {
				elapsed = 1
			}
			item.UploadBps = float64(n.windowUpload) / elapsed
			item.DownloadBps = float64(n.windowDownload) / elapsed
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Origin < out[j].Origin })
	return out
}
