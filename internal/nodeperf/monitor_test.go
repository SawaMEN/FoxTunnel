package nodeperf

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSamplesAndFailures(t *testing.T) {
	m := New()
	m.Begin("https://node.example")
	m.Observe("https://node.example", 20*time.Millisecond, 200, nil)
	m.Observe("https://node.example", 60*time.Millisecond, 503, nil)
	m.Observe("https://node.example", 40*time.Millisecond, 200, nil)
	m.Transfer("https://node.example", 1024, 2048)
	m.End("https://node.example")
	s := m.Snapshot()
	if len(s) != 1 || s[0].Samples != 3 || s[0].FailedRequests != 1 || s[0].RecentFailurePct < 33 || s[0].RequestLatencyMS <= 20 || s[0].JitterMS <= 0 || s[0].ActiveRequests != 0 || s[0].UploadedBytes != 1024 || s[0].DownloadedBytes != 2048 {
		t.Fatalf("unexpected sample: %+v", s)
	}
}

func TestRollingFailureWindow(t *testing.T) {
	m := New()
	for i := 0; i < recentWindow; i++ {
		m.Observe("https://n", time.Millisecond, 0, errors.New("fail"))
	}
	if got := m.Snapshot()[0].RecentFailurePct; got != 100 {
		t.Fatalf("got %.2f", got)
	}
	for i := 0; i < recentWindow; i++ {
		m.Observe("https://n", time.Millisecond, 200, nil)
	}
	if got := m.Snapshot()[0].RecentFailurePct; got != 0 {
		t.Fatalf("got %.2f", got)
	}
}

func TestBoundAndConcurrentReads(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Begin("https://same.example")
			m.Transfer("https://same.example", 12, 23)
			m.Observe("https://same.example", time.Millisecond, 200, nil)
			m.End("https://same.example")
		}()
	}
	wg.Wait()
	s := m.Snapshot()
	if len(s) != 1 || s[0].Samples != 80 || s[0].ActiveRequests != 0 || s[0].UploadedBytes != 960 || s[0].DownloadedBytes != 1840 {
		t.Fatalf("unexpected: %+v", s)
	}
	for i := 0; i < 70; i++ {
		m.Observe("https://other-"+string(rune(100+i)), time.Millisecond, 200, nil)
	}
	if len(m.Snapshot()) > maxOrigins {
		t.Fatal("unbounded origins")
	}
}

func TestEmptyOriginIgnored(t *testing.T) {
	m := New()
	m.Begin("")
	m.Transfer("", 1, 2)
	m.Observe("", time.Second, 500, nil)
	m.End("")
	if len(m.Snapshot()) != 0 {
		t.Fatal("unexpected origin")
	}
}
