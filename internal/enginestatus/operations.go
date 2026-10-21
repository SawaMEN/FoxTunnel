package enginestatus

import "time"

type Operation uint8

const (
	TCPSetup Operation = iota
	UDPExchange
	UDPStreamSetup
)

type Reason uint8

const (
	Success Reason = iota
	Canceled
	Timeout
	TrustFailed
	ProtocolFailed
	PeerRejected
	PeerLimited
	NetworkFailed
	Capacity
	NoResponse
	OtherFailure
)

func (r Reason) String() string {
	switch r {
	case Success:
		return "ok"
	case Canceled:
		return "canceled"
	case Timeout:
		return "timeout"
	case TrustFailed:
		return "tls_trust_failed"
	case ProtocolFailed:
		return "protocol_negotiation_failed"
	case PeerRejected:
		return "peer_rejected"
	case PeerLimited:
		return "peer_limited_or_unavailable"
	case NetworkFailed:
		return "network_failed"
	case Capacity:
		return "transport_capacity"
	case NoResponse:
		return "udp_no_response"
	default:
		return "other_failure"
	}
}

type Failures struct {
	Canceled uint64 `json:"canceled"`
	Timeout  uint64 `json:"timeout"`
	Trust    uint64 `json:"tls_trust_failed"`
	Protocol uint64 `json:"protocol_negotiation_failed"`
	Peer     uint64 `json:"peer_rejected"`
	Limited  uint64 `json:"peer_limited_or_unavailable"`
	Network  uint64 `json:"network_failed"`
	Capacity uint64 `json:"transport_capacity"`
	NoReply  uint64 `json:"udp_no_response"`
	Other    uint64 `json:"other_failure"`
}

type OperationStats struct {
	Started         uint64   `json:"started"`
	Succeeded       uint64   `json:"succeeded"`
	Failed          uint64   `json:"failed"`
	Active          uint64   `json:"active"`
	LastDurationUS  uint64   `json:"last_duration_us"`
	TotalDurationUS uint64   `json:"total_duration_us"`
	MaxDurationUS   uint64   `json:"max_duration_us"`
	LastReason      string   `json:"last_reason,omitempty"`
	Failures        Failures `json:"failures"`
}

type Rejection uint8

const (
	SDKCapacity Rejection = iota
	SOCKSCapacity
	UDPPendingCapacity
	UDPReceiveQueue
)

type Rejections struct {
	SDKCapacity       uint64 `json:"sdk_capacity"`
	SOCKSCapacity     uint64 `json:"socks_capacity"`
	UDPPending        uint64 `json:"udp_pending_capacity"`
	UDPReceiveDropped uint64 `json:"udp_receive_queue_drops"`
}

type RecoveryStats struct {
	AfterFailure          uint64 `json:"after_failure"`
	LastFailureRecoveryUS uint64 `json:"last_failure_recovery_us"`
	AfterNetworkChange    uint64 `json:"after_network_change"`
	LastNetworkRecoveryUS uint64 `json:"last_network_recovery_us"`
}

// Operations is fixed-size aggregate state: no destinations, peer error text,
// per-request history, callbacks or maps. Durations use the monotonic clock.
type Operations struct {
	TCP         OperationStats `json:"tcp_setup"`
	UDPExchange OperationStats `json:"udp_exchange"`
	UDPStream   OperationStats `json:"udp_stream_setup"`
	Rejections  Rejections     `json:"rejections"`
	Recovery    RecoveryStats  `json:"recovery"`
}

// Ticket belongs to exactly one Begin/Finish pair. Keep it local to the call;
// never reuse it or finish it twice. No request data is retained in a ticket.
type Ticket struct {
	kind             Operation
	started          time.Time
	network, failure uint64
	valid            bool
}

func (r *Recorder) operation(kind Operation) *OperationStats {
	switch kind {
	case TCPSetup:
		return &r.s.Operations.TCP
	case UDPExchange:
		return &r.s.Operations.UDPExchange
	case UDPStreamSetup:
		return &r.s.Operations.UDPStream
	default:
		return nil
	}
}

func (r *Recorder) BeginOperation(kind Operation) Ticket {
	if r == nil {
		return Ticket{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.operation(kind)
	if s == nil {
		return Ticket{}
	}
	s.Started++
	s.Active++
	r.s.UpdatedAt = time.Now().UTC()
	return Ticket{kind: kind, started: time.Now(), network: r.s.NetworkChanges, failure: r.failureEpoch, valid: true}
}

func microseconds(d time.Duration) uint64 {
	if d < 0 {
		return 0
	}
	return uint64(d.Microseconds())
}

func (r *Recorder) FinishOperation(ticket Ticket, reason Reason) {
	if r == nil || !ticket.valid {
		return
	}
	now := time.Now()
	duration := microseconds(now.Sub(ticket.started))
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.operation(ticket.kind)
	s.Active--
	s.LastDurationUS, s.TotalDurationUS = duration, s.TotalDurationUS+duration
	s.MaxDurationUS = max(s.MaxDurationUS, duration)
	s.LastReason = reason.String()
	r.s.UpdatedAt = now.UTC()
	if reason == Success {
		s.Succeeded++
		// Only a call started after the most recent failure/change can confirm
		// recovery. Older concurrent successes must not clear newer failures.
		if !r.failureSince.IsZero() && ticket.failure == r.failureEpoch {
			r.s.Operations.Recovery.AfterFailure++
			r.s.Operations.Recovery.LastFailureRecoveryUS = microseconds(now.Sub(r.failureSince))
			r.failureSince = time.Time{}
		}
		if !r.networkSince.IsZero() && ticket.network == r.s.NetworkChanges {
			r.s.Operations.Recovery.AfterNetworkChange++
			r.s.Operations.Recovery.LastNetworkRecoveryUS = microseconds(now.Sub(r.networkSince))
			r.networkSince = time.Time{}
		}
		return
	}
	s.Failed++
	switch reason {
	case Canceled:
		s.Failures.Canceled++
	case Timeout:
		s.Failures.Timeout++
	case TrustFailed:
		s.Failures.Trust++
	case ProtocolFailed:
		s.Failures.Protocol++
	case PeerRejected:
		s.Failures.Peer++
	case PeerLimited:
		s.Failures.Limited++
	case NetworkFailed:
		s.Failures.Network++
	case Capacity:
		s.Failures.Capacity++
	case NoResponse:
		s.Failures.NoReply++
	default:
		s.Failures.Other++
	}
	if reason != Canceled && reason != Capacity {
		r.failureEpoch++
		r.failureSince = now
	}
}

func (r *Recorder) Reject(kind Rejection) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.s.UpdatedAt = time.Now().UTC()
	switch kind {
	case SDKCapacity:
		r.s.Operations.Rejections.SDKCapacity++
	case SOCKSCapacity:
		r.s.Operations.Rejections.SOCKSCapacity++
	case UDPPendingCapacity:
		r.s.Operations.Rejections.UDPPending++
	case UDPReceiveQueue:
		r.s.Operations.Rejections.UDPReceiveDropped++
	}
}
