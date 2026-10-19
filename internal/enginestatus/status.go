// Package enginestatus records local, privacy-safe transport observations.
// Raw error strings, URLs, IPs, TLS identities and HTTP contents are excluded.
package enginestatus

import (
	"sync"
	"time"
)

// Snapshot is a thread-safe copy. A selected route does not mean an HTTP
// request succeeded, and the last route may differ from concurrent requests.
type Snapshot struct {
	Schema          int       `json:"schema"`
	Engine          string    `json:"engine"`
	Transport       string    `json:"transport"`
	TLSBackend      string    `json:"tls_backend"`
	QUICBackend     string    `json:"quic_backend"`
	H3Fallback      string    `json:"h3_fallback"`
	State           string    `json:"state"`
	LastRoute       string    `json:"last_route,omitempty"`
	LastReason      string    `json:"last_reason,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
	NetworkChanges  uint64    `json:"network_changes"`
	H3Probes        uint64    `json:"h3_probes"`
	H3Reachable     uint64    `json:"h3_reachable"`
	H3Unreachable   uint64    `json:"h3_unreachable"`
	H3ProbeRejected uint64    `json:"h3_probe_rejected"`
	H3Selected      uint64    `json:"h3_selected"`
	H2Selected      uint64    `json:"h2_selected"`
	ActiveProbes    int       `json:"active_probes"`
}

type Recorder struct {
	mu sync.Mutex
	s  Snapshot
}

func New() *Recorder {
	return &Recorder{s: Snapshot{
		Schema: 1, Engine: "legacy", Transport: "h2-connect",
		TLSBackend: "auto", QUICBackend: "quic-go",
		H3Fallback: "none", State: "configured",
	}}
}

func (r *Recorder) Configure(engine, transport, tlsBackend, quicBackend, fallback string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if engine == "" {
		engine = "legacy"
	}
	if transport == "" {
		transport = "h2-connect"
	}
	if tlsBackend == "" {
		tlsBackend = "auto"
	}
	if quicBackend == "" {
		quicBackend = "quic-go"
	}
	if fallback == "" {
		fallback = "none"
	}
	r.s.Engine, r.s.Transport, r.s.TLSBackend = engine, transport, tlsBackend
	r.s.QUICBackend, r.s.H3Fallback = quicBackend, fallback
	r.s.State, r.s.LastRoute, r.s.LastReason = "configured", "", ""
	r.s.UpdatedAt = time.Now().UTC()
}

func (r *Recorder) BeginProbe() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.s.H3Probes++
	r.s.ActiveProbes++
	r.mu.Unlock()
}

// EndProbe accepts fixed reason codes only, never an error message.
func (r *Recorder) EndProbe(outcome string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.s.ActiveProbes > 0 {
		r.s.ActiveProbes--
	}
	switch outcome {
	case "reachable":
		r.s.H3Reachable++
	case "unreachable":
		r.s.H3Unreachable++
	default:
		r.s.H3ProbeRejected++
	}
	r.mu.Unlock()
}

// Route records a pre-request choice, not a complete round trip.
func (r *Recorder) Route(route, reason string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	switch route {
	case "h3":
		r.s.H3Selected++
		r.s.State = "h3-selected"
	case "h2":
		r.s.H2Selected++
		r.s.State = "h2-selected"
	default:
		r.mu.Unlock()
		return
	}
	r.s.LastRoute, r.s.LastReason = route, reason
	r.s.UpdatedAt = time.Now().UTC()
	r.mu.Unlock()
}

func (r *Recorder) NetworkChanged() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.s.NetworkChanges++
	r.s.State, r.s.LastReason = "network-changed", "network-change"
	r.s.UpdatedAt = time.Now().UTC()
	r.mu.Unlock()
}

func (r *Recorder) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{Schema: 1, State: "unavailable"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.s
}
