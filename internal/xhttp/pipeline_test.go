package xhttp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketWindowWaitsForContiguousACK(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	c := &carrier{Conn: a, peer: b, cancel: cancel}
	defer c.Close()
	release := make(chan struct{})
	starts := make(chan uint64, 32)
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_, seq, _ := parsePath(r)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		if len(body) != clientPacketBytes || r.GetBody != nil {
			t.Error("unsafe body ownership")
		}
		// Record completion before WroteRequest releases the next POST worker;
		// observing after the callback can reorder notifications on another CPU.
		starts <- *seq
		if trace := httptrace.ContextClientTrace(r.Context()); trace != nil && trace.WroteRequest != nil {
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}
		if *seq == 0 {
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})
	done := make(chan struct{})
	u, _ := url.Parse("https://node" + Path + testID)
	go func() { sendPacketsWindow(c, ctx, transport, u, "token", "", Path, clientPacketWindow); close(done) }()
	writeDone := make(chan struct{})
	go func() { _, _ = a.Write(bytes.Repeat([]byte{37}, clientPacketBytes*20)); close(writeDone) }()
	for want := uint64(0); want < clientPacketWindow; want++ {
		select {
		case got := <-starts:
			if got != want {
				t.Fatal("body write ordering", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("pipeline did not fill")
		}
	}
	select {
	case seq := <-starts:
		t.Fatal("advanced past missing ACK", seq)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case seq := <-starts:
		if seq != clientPacketWindow {
			t.Fatal(seq)
		}
	case <-time.After(time.Second):
		t.Fatal("ACK did not release window")
	}
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("workers leaked")
	}
	<-writeDone
}

// A response arriving before the request body is written must not allow a
// later POST or buffer reuse, even with a nonstandard RoundTripper.
func TestPacketWindowEarlyResponseWaitsForWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	c := &carrier{Conn: a, peer: b, cancel: cancel}
	defer c.Close()
	entered := make(chan io.ReadCloser, 1)
	var calls atomic.Int64
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		entered <- r.Body
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	})
	u, _ := url.Parse("https://node" + Path + testID)
	done := make(chan struct{})
	go func() { sendPacketsWindow(c, ctx, transport, u, "token", "", Path, clientPacketWindow); close(done) }()
	go func() { _, _ = a.Write(bytes.Repeat([]byte{9}, clientPacketBytes*8)) }()
	var body io.ReadCloser
	select {
	case body = <-entered:
	case <-time.After(time.Second):
		t.Fatal("request not started")
	}
	if calls.Load() != 1 {
		t.Fatal("early response advanced pipeline")
	}
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("early-response worker retained")
	}
	if _, err := body.Read(make([]byte, 1)); err == nil {
		t.Fatal("closed body retained reusable payload")
	}
}

func TestPacketKnownLengthValidation(t *testing.T) {
	for _, test := range []struct {
		length int64
		body   string
		good   bool
	}{{3, "abc", true}, {0, "", true}, {2, "abc", false}, {4, "abc", false}, {MaxPacketBytes + 1, "", false}} {
		r := httptest.NewRequest("POST", "https://node", nil)
		r.ContentLength = test.length
		r.Body = io.NopCloser(bytes.NewBufferString(test.body))
		got, err := readPacket(r)
		if (err == nil) != test.good || test.good && string(got) != test.body {
			t.Fatal(test.length, err)
		}
	}
}

type delayedACKTransport struct {
	base  http.RoundTripper
	delay time.Duration
}

func (t delayedACKTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err != nil || r.Method != "POST" || t.delay == 0 {
		return resp, err
	}
	timer := time.NewTimer(t.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return resp, nil
	case <-r.Context().Done():
		resp.Body.Close()
		return nil, r.Context().Err()
	}
}
func BenchmarkPacketWindow(b *testing.B) {
	for _, delay := range []time.Duration{0, 40 * time.Millisecond} {
		for _, depth := range []int{1, clientPacketWindow} {
			b.Run("ack-"+strconv.Itoa(int(delay/time.Millisecond))+"ms/window-"+strconv.Itoa(depth), func(b *testing.B) {
				s := &Server{Authorized: func(*http.Request) bool { return true }, ServeConn: func(c net.Conn, _ *http.Request) { defer c.Close(); _, _ = io.Copy(c, c) }}
				server := httptest.NewUnstartedServer(s)
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				c, err := dialWithWindow(context.Background(), delayedACKTransport{server.Client().Transport, delay}, server.URL, "xhttp-packet-up", "token", "", Settings{}, depth)
				if err != nil {
					b.Fatal(err)
				}
				defer c.Close()
				payload := bytes.Repeat([]byte{17}, 256<<10)
				got := make([]byte, len(payload))
				exchange := func() {
					done := make(chan error, 1)
					go func() { _, err := c.Write(payload); done <- err }()
					if _, err := io.ReadFull(c, got); err != nil {
						b.Fatal(err)
					}
					if err := <-done; err != nil {
						b.Fatal(err)
					}
					if !bytes.Equal(got, payload) {
						b.Fatal("corrupt stream")
					}
				}
				exchange()
				b.SetBytes(int64(len(payload)))
				b.ReportAllocs()
				b.ResetTimer()
				for range b.N {
					exchange()
				}
			})
		}
	}
}
