//go:build linux

package bond

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// This models record request/reply delay and dropped delivery ACKs, NOT TCP
// packet loss. Both implementations pay the same delay on every logical record.
type recordLink struct {
	delay     time.Duration
	loseEvery uint64
	mu        sync.Mutex
	lost      map[string]bool
	requests  atomic.Int64
}
type recordState struct {
	op    byte
	seq   uint64
	token string
}

func (l *recordLink) wait(ctx context.Context) bool {
	if l.delay == 0 {
		return true
	}
	timer := time.NewTimer(l.delay / 2)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
func (l *recordLink) drop(s *recordState) bool {
	if l.loseEvery == 0 || s.op != opWrite || s.seq%l.loseEvery != 0 {
		return false
	}
	key := fmt.Sprintf("%s/%d", s.token, s.seq)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lost == nil {
		l.lost = make(map[string]bool)
	}
	if l.lost[key] {
		return false
	}
	l.lost[key] = true
	return true
}
func (l *recordLink) handler(h *Hub) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.requests.Add(1)
		state := &recordState{}
		lane := r.Header.Get(LaneHeader) == LaneVersion
		if lane {
			r.Body = &linkBody{ReadCloser: r.Body, link: l, ctx: r.Context(), state: state}
		} else {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				return
			}
			r.Body.Close()
			if len(data) >= headerSize {
				state.op = data[0]
				state.seq = binary.BigEndian.Uint64(data[33:41])
				state.token = string(data[1:33])
			}
			if !l.wait(r.Context()) {
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			// Buffer the builtin reply before simulating link delay. Sleeping
			// inside WriteHeader would hold the hub's session mutex and create
			// artificial serialization absent from the buffered HTTP writer.
			record := httptest.NewRecorder()
			h.ServeHTTP(record, r)
			if !l.wait(r.Context()) {
				return
			}
			if record.Code == 200 && l.drop(state) {
				panic(http.ErrAbortHandler)
			}
			for name, values := range record.Header() {
				w.Header()[name] = values
			}
			w.WriteHeader(record.Code)
			_, _ = w.Write(record.Body.Bytes())
			return
		}
		h.ServeHTTP(&linkWriter{ResponseWriter: w, link: l, ctx: r.Context(), state: state, lane: lane}, r)
	})
}

type linkBody struct {
	io.ReadCloser
	link    *recordLink
	ctx     context.Context
	state   *recordState
	bound   bool
	pending []byte
}

func (r *linkBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		if !r.bound {
			r.pending = make([]byte, 32)
			if _, err := io.ReadFull(r.ReadCloser, r.pending); err != nil {
				return 0, err
			}
			r.state.token = string(r.pending)
			r.bound = true
		} else {
			var prefix [8]byte
			if _, err := io.ReadFull(r.ReadCloser, prefix[:]); err != nil {
				return 0, err
			}
			n := binary.BigEndian.Uint32(prefix[:4])
			if n < headerSize || n > headerSize+chunkSize {
				return 0, io.ErrUnexpectedEOF
			}
			r.pending = make([]byte, 8+int(n))
			copy(r.pending, prefix[:])
			if _, err := io.ReadFull(r.ReadCloser, r.pending[8:]); err != nil {
				return 0, err
			}
			r.state.op = r.pending[8]
			r.state.seq = binary.BigEndian.Uint64(r.pending[8+33 : 8+41])
			if !r.link.wait(r.ctx) {
				return 0, r.ctx.Err()
			}
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

type linkWriter struct {
	http.ResponseWriter
	link    *recordLink
	ctx     context.Context
	state   *recordState
	lane    bool
	payload bool
}

func (w *linkWriter) Flush() { _ = http.NewResponseController(w.ResponseWriter).Flush() }
func (w *linkWriter) WriteHeader(status int) {
	if !w.lane {
		if !w.link.wait(w.ctx) {
			panic(http.ErrAbortHandler)
		}
		if status == 200 && w.link.drop(w.state) {
			panic(http.ErrAbortHandler)
		}
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *linkWriter) Write(p []byte) (int, error) {
	if w.lane {
		if w.payload {
			w.payload = false
		} else if len(p) == 6 {
			if !w.link.wait(w.ctx) {
				return 0, w.ctx.Err()
			}
			if binary.BigEndian.Uint16(p[:2]) == 200 && w.link.drop(w.state) {
				panic(http.ErrAbortHandler)
			}
			w.payload = binary.BigEndian.Uint32(p[2:]) > 0
		}
	}
	return w.ResponseWriter.Write(p)
}

func BenchmarkBondRecordLink(b *testing.B) {
	for _, model := range []struct {
		name  string
		delay time.Duration
		loss  uint64
	}{{"loopback", 0, 0}, {"recordRTT20ms", 20 * time.Millisecond, 0}, {"recordRTT20ms_ACKloss17", 20 * time.Millisecond, 17}} {
		for _, lanes := range []bool{false, true} {
			name := "rpc"
			if lanes {
				name = "lanes"
			}
			b.Run(model.name+"/"+name, func(b *testing.B) { benchmarkRecordLink(b, lanes, model.delay, model.loss) })
		}
	}
}
func benchmarkRecordLink(b *testing.B, lanes bool, delay time.Duration, loss uint64) {
	dial, _ := echoDial(b)
	h := &Hub{Dial: dial}
	b.Cleanup(func() { h.Close() })
	link := &recordLink{delay: delay, loseEvery: loss}
	var transport http.RoundTripper
	var endpoints []*url.URL
	for range 2 {
		server := httptest.NewUnstartedServer(link.handler(h))
		server.EnableHTTP2 = true
		server.StartTLS()
		b.Cleanup(server.Close)
		u, _ := url.Parse(server.URL)
		endpoints = append(endpoints, u)
		if transport == nil {
			transport = server.Client().Transport
			b.Cleanup(server.Client().CloseIdleConnections)
		}
	}
	client := &Client{Endpoints: endpoints, Transport: transport, Pipeline: 8, PersistentLanes: lanes}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	s, err := client.Open(ctx, "example.org:443")
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	data := bytes.Repeat([]byte("record-benchmark"), 1<<16)
	got := make([]byte, len(data))
	durations := make([]float64, 0, b.N)
	var before, after syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &before)
	requests := link.requests.Load()
	cgoCalls := runtime.NumCgoCall()
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		started := time.Now()
		done := make(chan error, 1)
		go func() { _, err := s.Write(data); done <- err }()
		if _, err := io.ReadFull(s, got); err != nil {
			b.Fatal(err)
		}
		if err := <-done; err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(data, got) {
			b.Fatal("corrupted data")
		}
		durations = append(durations, float64(time.Since(started))/float64(time.Millisecond))
	}
	b.StopTimer()
	syscall.Getrusage(syscall.RUSAGE_SELF, &after)
	slices.Sort(durations)
	b.ReportMetric(durations[(95*len(durations)+99)/100-1], "p95-ms")
	b.ReportMetric(float64(link.requests.Load()-requests)/float64(b.N), "HTTP/op")
	cpu := func(r syscall.Rusage) float64 {
		return float64(r.Utime.Sec+r.Stime.Sec)*1e6 + float64(r.Utime.Usec+r.Stime.Usec)
	}
	b.ReportMetric((cpu(after)-cpu(before))/float64(b.N), "CPU-us/op")
	b.ReportMetric(float64(after.Maxrss), "process-peak-KiB")
	b.ReportMetric(float64(runtime.NumCgoCall()-cgoCalls)/float64(b.N), "cgo/op")
}
