package bond

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func adaptiveTestClient() *Client {
	a, _ := url.Parse("https://slow.example")
	b, _ := url.Parse("https://fast.example")
	return &Client{Endpoints: []*url.URL{a, b}, Adaptive: true}
}

func TestAdaptiveBondThroughputMeasurements(t *testing.T) {
	c := adaptiveTestClient()
	for i := 0; i < 4; i++ {
		index, done := c.reserveFor([]bool{false, true}, opWrite, chunkSize)
		if index != 0 {
			t.Fatalf("forced slow path %d", index)
		}
		done(2*time.Second, false, chunkSize)
		index, done = c.reserveFor([]bool{true, false}, opWrite, chunkSize)
		if index != 1 {
			t.Fatalf("forced fast path %d", index)
		}
		done(60*time.Millisecond, false, chunkSize)
	}
	index, done := c.reserveFor([]bool{false, false}, opWrite, chunkSize)
	if index != 1 {
		t.Fatalf("adaptive scheduler ignored measured delivery: %d", index)
	}
	done(65*time.Millisecond, false, chunkSize)
	metrics := c.PathMetrics()
	if len(metrics) != 2 || metrics[1].UploadSamples < 4 ||
		metrics[1].UploadBps <= metrics[0].UploadBps || metrics[0].InFlightBytes != 0 ||
		metrics[1].PendingRequests != 0 {
		t.Fatalf("incorrect measurements: %+v", metrics)
	}
}

func TestAdaptiveBondBacklogSplitsWork(t *testing.T) {
	c := adaptiveTestClient()
	c.paths = make([]pathState, 2)
	now := time.Now()
	c.paths[0] = pathState{uploadBps: 320000, uploadSamples: 5, lastUpload: now, latency: 35 * time.Millisecond}
	c.paths[1] = pathState{uploadBps: 500000, uploadSamples: 5, lastUpload: now, latency: 25 * time.Millisecond,
		inflightBytes: 7 * chunkSize, pending: 7}
	index, done := c.reserveFor([]bool{false, false}, opWrite, chunkSize)
	if index != 0 {
		t.Fatalf("queue-aware scheduler failed to distribute data: %d", index)
	}
	done(100*time.Millisecond, false, 0)
}

func TestAdaptiveBondSlowPathSuppressedButRetainsFallback(t *testing.T) {
	c := adaptiveTestClient()
	c.paths = make([]pathState, 2)
	now := time.Now()
	c.paths[0] = pathState{uploadBps: 8000, uploadSamples: 5, lastUpload: now, latency: 200 * time.Millisecond}
	c.paths[1] = pathState{uploadBps: 700000, uploadSamples: 5, lastUpload: now, latency: 20 * time.Millisecond}
	index, done := c.reserveFor([]bool{false, false}, opWrite, chunkSize)
	if index != 1 {
		t.Fatalf("head-of-line risk selected slow path: %d", index)
	}
	done(50*time.Millisecond, false, chunkSize)
	c.mu.Lock()
	c.paths[1].retryAt = time.Now().Add(time.Minute)
	c.mu.Unlock()
	index, done = c.reserveFor([]bool{false, false}, opWrite, chunkSize)
	if index != 0 {
		t.Fatalf("slow fallback was excluded during fast-path outage: %d", index)
	}
	done(time.Second, false, chunkSize)
}

func TestAdaptiveBondColdStartRotatesRealBlocks(t *testing.T) {
	c := adaptiveTestClient()
	counts := [2]int{}
	for i := 0; i < 8; i++ {
		index, done := c.reserveFor([]bool{false, false}, opWrite, chunkSize)
		counts[index]++
		done(100*time.Millisecond, false, 0) // no goodput measurements
	}
	if counts[0] < 3 || counts[1] < 3 {
		t.Fatalf("cold traffic pinned one path: %+v", counts)
	}
}

func TestAdaptiveBondSmallOrFailedPayloadIsNotThroughput(t *testing.T) {
	c := adaptiveTestClient()
	for _, tc := range []struct {
		size    int
		failed  bool
		elapsed time.Duration
	}{
		{500, false, 50 * time.Millisecond},
		{chunkSize, true, 50 * time.Millisecond},
		{chunkSize, false, 0},
		{chunkSize, false, 11 * time.Second},
	} {
		index, done := c.reserveFor([]bool{false, true}, opWrite, tc.size)
		if index != 0 {
			t.Fatal(index)
		}
		done(tc.elapsed, tc.failed, tc.size)
	}
	m := c.PathMetrics()
	if m[0].UploadSamples != 0 || m[0].PendingRequests != 0 || m[0].InFlightBytes != 0 {
		t.Fatalf("invalid traffic counted: %+v", m)
	}
}

func TestAdaptiveBondNetworkChangeDiscardsOldSamples(t *testing.T) {
	c := adaptiveTestClient()
	index, done := c.reserveFor([]bool{false, true}, opWrite, chunkSize)
	if index != 0 {
		t.Fatal(index)
	}
	c.ResetRouteQuality()
	done(20*time.Millisecond, false, chunkSize)
	m := c.PathMetrics()
	if m[0].UploadSamples != 0 || m[0].InFlightBytes != 0 || m[0].PendingRequests != 0 {
		t.Fatalf("old-network reply contaminated quality: %+v", m[0])
	}
}

func TestAdaptiveBondConcurrentReservations(t *testing.T) {
	c := adaptiveTestClient()
	var wg sync.WaitGroup
	for i := 0; i < 80; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, done := c.reserveFor([]bool{false, false}, opRead, 0)
			done(20*time.Millisecond, false, chunkSize)
		}()
	}
	wg.Wait()
	for _, m := range c.PathMetrics() {
		if m.InFlightBytes != 0 || m.PendingRequests != 0 {
			t.Fatalf("leaked reservation: %+v", m)
		}
	}
}

type adaptiveRoundTripFunc func(*http.Request) (*http.Response, error)

func (f adaptiveRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestAdaptiveBondRecordsAckedUploadOnly(t *testing.T) {
	c := adaptiveTestClient()
	c.Transport = adaptiveRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatal("expected bond POST")
		}
		// Real HTTP exchanges take measurable time; the estimator explicitly
		// discards sub-millisecond loopback artifacts.
		time.Sleep(2 * time.Millisecond)
		return &http.Response{
			StatusCode: http.StatusOK, ProtoMajor: 2,
			Body: io.NopCloser(strings.NewReader("")), ContentLength: 0,
		}, nil
	})
	payload := make([]byte, chunkSize)
	_, err := c.requestVia(t.Context(), c.Transport, make([]byte, 32), "", opWrite, 0, 0, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	metrics := c.PathMetrics()
	var samples uint64
	for _, item := range metrics {
		samples += item.UploadSamples
	}
	if samples != 1 {
		t.Fatalf("successful ACK did not record one upload sample: %+v", metrics)
	}
}

func TestAdaptiveBondReplayDoesNotInflateGoodput(t *testing.T) {
	c := adaptiveTestClient()
	var attempts int
	c.Transport = adaptiveRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, io.ErrUnexpectedEOF
		}
		time.Sleep(2 * time.Millisecond)
		return &http.Response{
			StatusCode: http.StatusOK, ProtoMajor: 2,
			Body: io.NopCloser(strings.NewReader("")), ContentLength: 0,
		}, nil
	})
	_, err := c.requestVia(t.Context(), c.Transport, make([]byte, 32), "", opWrite, 1, 0, make([]byte, chunkSize), nil)
	if err != nil || attempts != 2 {
		t.Fatalf("retry did not recover: attempts=%d err=%v", attempts, err)
	}
	for _, metric := range c.PathMetrics() {
		if metric.UploadSamples != 0 {
			t.Fatalf("replayed ACK inflated speed: %+v", metric)
		}
	}
}
