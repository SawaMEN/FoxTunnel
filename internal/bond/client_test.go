package bond

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
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
