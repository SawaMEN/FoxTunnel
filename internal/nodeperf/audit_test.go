package nodeperf

import (
	"testing"
	"time"
)

func TestAuditNetworkChangeInvalidatesOldRates(t *testing.T) {
	m := New()
	m.Transfer("https://node.example", 32768, 32768)
	m.Observe("https://node.example", time.Millisecond, 200, nil)
	m.InvalidateQuality()
	s := m.Snapshot()[0]
	if s.UploadedBytes != 32768 || s.DownloadedBytes != 32768 {
		t.Fatal("cumulative traffic lost")
	}
	if s.UploadBps != 0 || s.DownloadBps != 0 {
		t.Fatalf("old-network rates survived invalidation: %v %v", s.UploadBps, s.DownloadBps)
	}
}
