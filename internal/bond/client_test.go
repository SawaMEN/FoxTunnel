package bond

import (
	"bytes"
	"context"
	"encoding/binary"
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
		if r.ContentLength > headerSize && r.Header.Get("X-FoxTunnel-Bond-Hub") != "" && first.CompareAndSwap(false, true) {
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
