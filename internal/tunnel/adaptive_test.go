package tunnel

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdaptiveSchedulerUsesMetricsAndExistingCooldown(t *testing.T) {
	c, err := NewClient("https://a.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetFallbackServers([]string{"https://b.example"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetBalance("adaptive"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		c.nodeMetrics.Observe("https://a.example", 100*time.Millisecond, 200, nil)
		c.nodeMetrics.Observe("https://b.example", 12*time.Millisecond, 200, nil)
	}
	selected, release := c.reserveEndpoint([]bool{false, false})
	if selected != 1 {
		t.Fatalf("better observed route not selected: %d", selected)
	}
	release()
	release() // idempotent per-stream reservation
	c.schedulerMu.Lock()
	active := c.activeEndpoints[1]
	c.schedulerMu.Unlock()
	if active != 0 {
		t.Fatalf("reservation not released: %d", active)
	}
	c.endpointResult(1, true)
	selected, release = c.reserveEndpoint([]bool{false, false})
	if selected != 0 {
		t.Fatalf("cooldown ignored: %d", selected)
	}
	release()
	c.NotifyNetworkChange()
	if got := c.NodeStatus(); len(got) == 0 || got[0].SuccessfulResponses != 0 {
		t.Fatalf("network change kept stale quality: %+v", got)
	}
	c.schedulerMu.Lock()
	retry := c.endpointRetryAt[1]
	c.schedulerMu.Unlock()
	if !retry.IsZero() {
		t.Fatal("network change kept stale cooldown")
	}
}

func TestAdaptiveNeverRetriesTerminalHTTP(t *testing.T) {
	var backupCalls atomic.Int64
	c, addr := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backupCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	backup := c.ServerURL.String()
	primary := setupEndpoint(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	usePrimary(t, c, primary.URL)
	if err := c.SetFallbackServers([]string{backup}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetBalance("adaptive"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	conn, code := connectSOCKS(t, addr, "example.com:443")
	conn.Close()
	if code == 0 || backupCalls.Load() != 0 {
		t.Fatalf("terminal HTTP error retried: code=%d backup=%d", code, backupCalls.Load())
	}
}

func TestAdaptiveModeValidation(t *testing.T) {
	c, err := NewClient("https://a.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetBalance("adaptive"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetBalance("invalid"); err == nil {
		t.Fatal("invalid balance mode accepted")
	}
}

func TestAdaptiveBondCombinationRejectedInCore(t *testing.T) {
	c, err := NewClient("https://a.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetFallbackServers([]string{"https://b.example"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetBalance("adaptive"); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableBond(); err == nil {
		t.Fatal("unsupported adaptive bonding accepted")
	}
	if err := c.SetBalance("failover"); err != nil {
		t.Fatal(err)
	}
	if err := c.EnableBond(); err != nil {
		t.Fatal(err)
	}
	if err := c.SetBalance("adaptive"); err == nil {
		t.Fatal("adaptive mode allowed after bond enabled")
	}
}
