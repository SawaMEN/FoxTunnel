package enginestatus

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestOperationConcurrencyAndSnapshotIsolation(t *testing.T) {
	r := New()
	var workers sync.WaitGroup
	for range 12 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range 200 {
				ticket := r.BeginOperation(Operation(i % 3))
				reason := Success
				if i%2 == 0 {
					reason = NetworkFailed
				}
				r.FinishOperation(ticket, reason)
				s := r.Snapshot().Operations
				for _, op := range []OperationStats{s.TCP, s.UDPExchange, s.UDPStream} {
					if op.Started != op.Succeeded+op.Failed+op.Active || op.LastDurationUS > op.MaxDurationUS || op.MaxDurationUS > op.TotalDurationUS {
						t.Error("inconsistent concurrent snapshot")
					}
				}
			}
		}()
	}
	workers.Wait()
	s := r.Snapshot()
	o := s.Operations
	if o.TCP.Started+o.UDPExchange.Started+o.UDPStream.Started != 2400 || o.TCP.Failed+o.UDPExchange.Failed+o.UDPStream.Failed != 1200 || o.TCP.Active+o.UDPExchange.Active+o.UDPStream.Active != 0 {
		t.Fatal("lost operations under concurrent load", o)
	}
	s.Operations.TCP.LastReason = "private-marker"
	if r.Snapshot().Operations.TCP.LastReason == "private-marker" {
		t.Fatal("snapshot mutates recorder state")
	}
}

func TestRecoveryRequiresCallStartedAfterFailureOrNetworkChange(t *testing.T) {
	r := New()
	old := r.BeginOperation(TCPSetup)
	r.NetworkChanged()
	failed := r.BeginOperation(TCPSetup)
	r.FinishOperation(failed, NetworkFailed)
	r.FinishOperation(old, Success)
	if got := r.Snapshot().Operations.Recovery; got.AfterFailure != 0 || got.AfterNetworkChange != 0 {
		t.Fatal("old in-flight success incorrectly confirmed recovery", got)
	}
	fresh := r.BeginOperation(UDPStreamSetup)
	r.FinishOperation(fresh, Success)
	if got := r.Snapshot().Operations.Recovery; got.AfterFailure != 1 || got.AfterNetworkChange != 1 {
		t.Fatal("new successful operation failed to confirm recovery", got)
	}
	stale := r.BeginOperation(TCPSetup)
	r.NetworkChanged()
	r.NetworkChanged()
	r.FinishOperation(stale, Success)
	if got := r.Snapshot().Operations.Recovery; got.AfterNetworkChange != 1 {
		t.Fatal("coalesced network changes accepted an old success", got)
	}
	r.FinishOperation(r.BeginOperation(TCPSetup), Success)
	r.FinishOperation(r.BeginOperation(TCPSetup), Success)
	if got := r.Snapshot().Operations.Recovery; got.AfterNetworkChange != 2 || got.AfterFailure != 1 {
		t.Fatal("recovery counted twice", got)
	}
}

func TestStatusNeverRetainsArbitraryLabels(t *testing.T) {
	r := New()
	r.Configure("private-marker", "https://private-marker", "private-marker", "private-marker", "private-marker")
	r.Route("h2", "private-marker")
	r.FinishOperation(r.BeginOperation(TCPSetup), Reason(255))
	for _, reason := range []Reason{Canceled, Timeout, TrustFailed, ProtocolFailed, PeerRejected, PeerLimited, NetworkFailed, Capacity, NoResponse} {
		r.FinishOperation(r.BeginOperation(UDPExchange), reason)
	}
	for _, kind := range []Rejection{SDKCapacity, SOCKSCapacity, UDPPendingCapacity, UDPReceiveQueue} {
		r.Reject(kind)
	}
	s := r.Snapshot()
	encoded, err := json.Marshal(s)
	if err != nil || strings.Contains(string(encoded), "private-marker") || len(encoded) > 8192 {
		t.Fatal("unbounded or unsafe status output", err)
	}
	var oldReader struct {
		Schema int    `json:"schema"`
		State  string `json:"state"`
	}
	if err := json.Unmarshal(encoded, &oldReader); err != nil || oldReader.Schema != 1 || oldReader.State != "h2-selected" {
		t.Fatal("additive metrics broke the existing JSON schema", err)
	}
	var absent *Recorder
	absent.FinishOperation(absent.BeginOperation(TCPSetup), Success)
	absent.Reject(SDKCapacity)
}
