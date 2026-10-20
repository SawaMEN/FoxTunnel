package bond

import (
	"bytes"
	"context"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the real HTTP/2 Bond carrier through two independent ingress
// listeners sharing one hub. A delay is injected into the application-level
// HTTP operation, not the underlying packet network: this proves integrity
// and concurrent ingress use, not a WAN throughput or ping improvement.
func TestAdaptiveBondHTTP2MultiIngressIntegrity(t *testing.T) {
	dial, dials := echoDial(t)
	c, _, _ := laneFixture(t, dial)
	c.PersistentLanes = false
	c.Pipeline = 0
	c.Adaptive = true
	c.AutoTune = true

	base := c.Transport
	var writes [2]atomic.Int64
	c.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.ContentLength >= headerSize+adaptiveMinBytes {
			if req.URL.Host == c.Endpoints[0].Host {
				writes[0].Add(1)
			} else if req.URL.Host == c.Endpoints[1].Host {
				writes[1].Add(1)
			} else {
				t.Errorf("unexpected ingress: %s", req.URL.Host)
			}
		}
		// Make ACKed operation samples measurable even on fast local CI.
		time.Sleep(3 * time.Millisecond)
		return base.RoundTrip(req)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := c.Open(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	payload := bytes.Repeat([]byte("FoxTunnel-adaptive-bond-v1!"), 1<<15)
	done := make(chan error, 1)
	go func() {
		_, err := s.Write(payload)
		if err == nil {
			err = s.CloseWrite()
		}
		done <- err
	}()
	received, readErr := io.ReadAll(s)
	writeErr := <-done
	if readErr != nil || writeErr != nil {
		t.Fatalf("multi-ingress transfer: read=%v write=%v", readErr, writeErr)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("reordered, duplicated or truncated Bond data: got %d bytes, want %d", len(received), len(payload))
	}
	if dials.Load() != 1 {
		t.Fatalf("Bond session redialed destination %d times", dials.Load())
	}
	if writes[0].Load() == 0 || writes[1].Load() == 0 {
		t.Fatalf("both ingress links must carry real blocks: %d / %d", writes[0].Load(), writes[1].Load())
	}
	metrics := c.PathMetrics()
	if metrics[0].UploadSamples+metrics[1].UploadSamples == 0 {
		t.Fatalf("no ACKed block measurements: %+v", metrics)
	}
	for _, metric := range metrics {
		if metric.InFlightBytes != 0 || metric.PendingRequests < 0 {
			t.Fatalf("leaked upload reservation: %+v", metric)
		}
	}
}

func TestAdaptivePickNeverSelectsTriedPath(t *testing.T) {
	random := rand.New(rand.NewSource(801))
	now := time.Now()
	for size := 2; size <= 8; size++ {
		endpoints := make([]*url.URL, size)
		paths := make([]pathState, size)
		for i := range endpoints {
			endpoints[i] = &url.URL{Scheme: "https", Host: "example.org"}
		}
		c := &Client{Endpoints: endpoints, paths: paths, Adaptive: true}
		for sample := 0; sample < 200; sample++ {
			tried := make([]bool, size)
			eligible := 0
			for i := range tried {
				tried[i] = random.Intn(3) == 0
				if !tried[i] {
					eligible++
				}
				p := &c.paths[i]
				p.pending = random.Intn(8)
				p.inflightBytes = int64(random.Intn(8) * chunkSize)
				p.uploadBps = float64(20_000 + random.Intn(10_000_000))
				p.downloadBps = float64(20_000 + random.Intn(10_000_000))
				p.uploadSamples, p.downloadSamples = 5, 5
				p.lastUpload, p.lastDownload = now, now
				p.latency = time.Duration(1+random.Intn(200)) * time.Millisecond
				p.retryAt = time.Time{}
				if random.Intn(3) == 0 {
					p.retryAt = now.Add(time.Duration(1+random.Intn(10)) * time.Second)
				}
			}
			if eligible == 0 {
				continue
			}
			c.next = uint64(random.Intn(1000))
			op := opWrite
			if sample%2 == 0 {
				op = opRead
			}
			picked := c.pickAdaptive(tried, op, chunkSize, now)
			if picked < 0 || picked >= size || tried[picked] {
				t.Fatalf("unsafe choice with %d ingress paths: picked=%d tried=%v", size, picked, tried)
			}
			anyReady := false
			for i := range tried {
				anyReady = anyReady || (!tried[i] && !now.Before(c.paths[i].retryAt))
			}
			if anyReady && now.Before(c.paths[picked].retryAt) {
				t.Fatalf("selected cooling ingress despite usable alternative: %d", picked)
			}
		}
	}
}

func TestAdaptivePickHotPathNoAllocations(t *testing.T) {
	c := adaptiveTestClient()
	now := time.Now()
	c.paths = []pathState{
		{latency: 40 * time.Millisecond, uploadBps: 3e6, uploadSamples: 5, lastUpload: now},
		{latency: 70 * time.Millisecond, uploadBps: 1e6, uploadSamples: 5, lastUpload: now},
	}
	tried := []bool{false, false}
	if got := testing.AllocsPerRun(100, func() {
		if c.pickAdaptive(tried, opWrite, chunkSize, now) < 0 {
			panic("no eligible ingress")
		}
	}); got != 0 {
		t.Fatalf("per-block adaptive selection allocated %.2f times", got)
	}
}

func BenchmarkBondAdaptivePick(b *testing.B) {
	for _, count := range []int{2, 8} {
		b.Run(map[int]string{2: "two_ingress", 8: "eight_ingress"}[count], func(b *testing.B) {
			now := time.Now()
			c := &Client{Endpoints: make([]*url.URL, count), paths: make([]pathState, count), Adaptive: true}
			for i := range c.paths {
				c.Endpoints[i] = &url.URL{Scheme: "https", Host: "example.org"}
				c.paths[i] = pathState{
					latency:       time.Duration(20+5*i) * time.Millisecond,
					uploadBps:     float64(5_000_000 / (i + 1)),
					uploadSamples: 5, lastUpload: now,
				}
			}
			tried := make([]bool, count)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c.next = uint64(i)
				_ = c.pickAdaptive(tried, opWrite, chunkSize, now)
			}
		})
	}
}
