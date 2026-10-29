package bond

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWeightedPendingAndCooldown(t *testing.T) {
	a, _ := url.Parse("https://a.example")
	b, _ := url.Parse("https://b.example")
	c := &Client{Endpoints: []*url.URL{a, b}, Weights: []int{4, 1}, paths: []pathState{{latency: time.Millisecond}, {latency: time.Millisecond}}}
	var counts [2]int
	var releases []func(time.Duration, bool)
	for range 100 {
		index, done := c.reserve([]bool{false, false})
		counts[index]++
		releases = append(releases, done)
	}
	if counts[0] != 80 || counts[1] != 20 {
		t.Fatalf("capacity weighting: %v", counts)
	}
	for _, done := range releases {
		done(time.Millisecond, false)
	}
	index, done := c.reserve([]bool{false, true})
	if index != 0 {
		t.Fatal("wrong forced path")
	}
	done(0, true)
	index, done = c.reserve([]bool{false, false})
	defer done(time.Millisecond, false)
	if index != 1 {
		t.Fatal("high weight overrode failed-node cooldown")
	}
}

func TestOpenPinsCoordinatorHubBeforeDial(t *testing.T) {
	a, _ := url.Parse("https://a.example")
	expected := strings.Repeat("ab", 32)
	c := &Client{Endpoints: []*url.URL{a}, Weights: []int{1}, ExpectedHub: expected, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Vetroff-Bond-Hub") != expected {
			t.Error("open did not carry pinned hub")
		}
		return &http.Response{StatusCode: 200, ProtoMajor: 2, ContentLength: 32, Body: io.NopCloser(bytes.NewReader(make([]byte, 32)))}, nil
	})}
	if _, err := c.Open(context.Background(), "example.org:443"); err == nil {
		t.Fatal("different exit identity accepted")
	}
}
func TestSmallWritesUseConcurrentPaths(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	var active, peak atomic.Int64
	var calls [2]atomic.Int64
	a, _ := url.Parse("https://a.example")
	b, _ := url.Parse("https://b.example")
	c := &Client{Endpoints: []*url.URL{a, b}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		if body[0] == opWrite {
			index := 0
			if r.URL.Host == "b.example" {
				index = 1
			}
			calls[index].Add(1)
			n := active.Add(1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			if n == 4 {
				close(ready)
			}
			select {
			case <-release:
			case <-r.Context().Done():
				active.Add(-1)
				return nil, r.Context().Err()
			}
			active.Add(-1)
		}
		response := []byte(nil)
		if body[0] == opOpen {
			response = make([]byte, 32)
		}
		return &http.Response{StatusCode: 200, ProtoMajor: 2, ContentLength: int64(len(response)), Body: io.NopCloser(bytes.NewReader(response))}, nil
	})}
	s, err := c.Open(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for range 4 {
		if _, err := s.Write([]byte("small")); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("small writes were serialized")
	}
	close(release)
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if peak.Load() != 4 || calls[0].Load() == 0 || calls[1].Load() == 0 {
		t.Fatalf("peak=%d paths=%d/%d", peak.Load(), calls[0].Load(), calls[1].Load())
	}
}

// Reading fewer bytes than a block must retain its receive slot until the last
// byte is consumed, including while three later fetches complete concurrently.
func TestPartialReadsAcrossReceiveSlotReuse(t *testing.T) {
	a, _ := url.Parse("https://a.example")
	b, _ := url.Parse("https://b.example")
	c := &Client{Endpoints: []*url.URL{a, b}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		status := 200
		var data []byte
		switch body[0] {
		case opOpen:
			data = make([]byte, 32)
		case opRead:
			seq := binary.BigEndian.Uint64(body[33:41])
			if seq >= 12 {
				status = 201
			} else {
				data = bytes.Repeat([]byte{byte(seq)}, 1024)
			}
		}
		return &http.Response{StatusCode: status, ProtoMajor: 2, ContentLength: int64(len(data)), Body: io.NopCloser(bytes.NewReader(data))}, nil
	})}
	s, err := c.Open(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var actual bytes.Buffer
	part := make([]byte, 17)
	for {
		n, err := s.Read(part)
		actual.Write(part[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	var expected bytes.Buffer
	for seq := range 12 {
		expected.Write(bytes.Repeat([]byte{byte(seq)}, 1024))
	}
	if !bytes.Equal(actual.Bytes(), expected.Bytes()) {
		t.Fatal("receive slot overwritten before consumption")
	}
	if _, err := s.Read(part); err != io.EOF {
		t.Fatal("EOF is not stable", err)
	}
}

func TestRetriedUploadClosesOldBodyBeforeBufferReuse(t *testing.T) {
	a, _ := url.Parse("https://a.example")
	b, _ := url.Parse("https://b.example")
	var first atomic.Bool
	oldBody := make(chan io.ReadCloser, 2)
	c := &Client{Endpoints: []*url.URL{a, b}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.ContentLength > headerSize && r.Header.Get("X-Vetroff-Bond-Hub") != "" && first.CompareAndSwap(false, true) {
			oldBody <- r.Body
			rewind, err := r.GetBody()
			if err != nil {
				t.Error(err)
			} else {
				oldBody <- rewind
			}
			r.Body.Close()
			return nil, context.DeadlineExceeded
		}
		body, _ := io.ReadAll(r.Body)
		var data []byte
		if len(body) > 0 && body[0] == opOpen {
			data = make([]byte, 32)
		}
		return &http.Response{StatusCode: 200, ProtoMajor: 2, ContentLength: int64(len(data)), Body: io.NopCloser(bytes.NewReader(data))}, nil
	})}
	s, err := c.Open(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	for n := range 8 {
		if _, err := s.Write(bytes.Repeat([]byte{byte(n)}, chunkSize)); err != nil {
			t.Fatal(err)
		}
		s.uploadPending.Wait()
	}
	for range 2 {
		select {
		case reader := <-oldBody:
			data, err := io.ReadAll(reader)
			if err != io.ErrClosedPipe || len(data) != 0 {
				t.Fatal("old/rewound transport body still reads a reused upload slot", len(data), err)
			}
		default:
			t.Fatal("retry/rewind not exercised")
		}
	}
	s.Close()
	if _, err := s.Write([]byte("after close")); err == nil {
		t.Fatal("write accepted after close")
	}
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("read scheduled work after close")
	}
}

func TestAdaptivePipelineAndPollMeasurements(t *testing.T) {
	c := &Client{paths: []pathState{{latency: 40 * time.Millisecond}, {latency: 60 * time.Millisecond}}}
	if c.pipelineDepth() != 8 {
		t.Fatal("high-delay paths did not expand pipeline")
	}
	c.paths[1].latency = time.Millisecond
	if c.pipelineDepth() != 4 {
		t.Fatal("fast measured alternative ignored")
	}
	c.paths[1].retryAt = time.Now().Add(time.Second)
	if c.pipelineDepth() != 8 {
		t.Fatal("cooling path affected pipeline")
	}
	c.Pipeline = 4
	if c.pipelineDepth() != 4 {
		t.Fatal("fixed pipeline ignored")
	}
	c.Pipeline = 8
	if c.pipelineDepth() != 8 {
		t.Fatal("fixed pipeline ignored")
	}
	a, _ := url.Parse("https://a.example")
	b, _ := url.Parse("https://b.example")
	c = &Client{Endpoints: []*url.URL{a, b}, paths: []pathState{{latency: time.Millisecond}, {latency: time.Millisecond}}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 204, ProtoMajor: 2, ContentLength: 0, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})}
	_, err := c.request(context.Background(), make([]byte, 32), "hub", opRead, 0, 0, nil)
	if !errors.Is(err, errPoll) || c.paths[0].latency != time.Millisecond {
		t.Fatal("empty long poll changed path latency", err)
	}
}
func TestAttemptBudgetWithMeasuredAlternative(t *testing.T) {
	c := &Client{AttemptTimeout: 3 * time.Second, paths: []pathState{{latency: 10 * time.Millisecond}, {latency: time.Second}}}
	if got := c.attemptBudget(1, opWrite); got != 250*time.Millisecond {
		t.Fatal(got)
	}
	if got := c.attemptBudget(1, opOpen); got != 3*time.Second {
		t.Fatal("open budget shortened", got)
	}
	c.paths[0].retryAt = time.Now().Add(time.Second)
	if got := c.attemptBudget(1, opRead); got != 3*time.Second {
		t.Fatal("cooling alternative shortened budget", got)
	}
	c.paths[0].retryAt = time.Time{}
	c.paths[0].latency = 100 * time.Millisecond
	if got := c.attemptBudget(1, opRead); got != 400*time.Millisecond {
		t.Fatal(got)
	}
	c.AttemptTimeout = 200 * time.Millisecond
	if got := c.attemptBudget(1, opWrite); got != 200*time.Millisecond {
		t.Fatal("configured cap exceeded", got)
	}
}
func TestEightUploadSlotsCanRunTogether(t *testing.T) {
	ready := make(chan struct{})
	release := make(chan struct{})
	var active atomic.Int64
	a, _ := url.Parse("https://a.example")
	b, _ := url.Parse("https://b.example")
	c := &Client{Pipeline: 8, Endpoints: []*url.URL{a, b}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		var data []byte
		if body[0] == opOpen {
			data = make([]byte, 32)
		}
		if body[0] == opWrite {
			if active.Add(1) == 8 {
				close(ready)
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return &http.Response{StatusCode: 200, ProtoMajor: 2, ContentLength: int64(len(data)), Body: io.NopCloser(bytes.NewReader(data))}, nil
	})}
	s, err := c.Open(context.Background(), "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for range 8 {
		if _, err := s.Write([]byte("block")); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("eight slots were not active")
	}
	close(release)
	if err := s.CloseWrite(); err != nil {
		t.Fatal(err)
	}
}
