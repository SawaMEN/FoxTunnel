package bond

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Both entries lose the first response to each operation after the shared hub
// has processed it. Recovery must reuse one session and deliver bytes once.
func TestRecoverAfterEveryEntryLosesAcknowledgement(t *testing.T) {
	payload := bytes.Repeat([]byte("one destination, one delivery;"), 128)
	var dials atomic.Int64
	delivered := make(chan []byte, 8)
	hub := &Hub{Dial: func(context.Context, string) (net.Conn, error) {
		dials.Add(1)
		local, peer := net.Pipe()
		go func() {
			defer peer.Close()
			got := make([]byte, len(payload))
			_, err := io.ReadFull(peer, got)
			if err == nil {
				_, _ = peer.Write(got)
			}
			delivered <- got
		}()
		return local, nil
	}}
	defer hub.Close()
	a, _ := url.Parse("https://a.example")
	b, _ := url.Parse("https://b.example")
	var mu sync.Mutex
	lost := make(map[byte]map[string]bool)
	client := &Client{Endpoints: []*url.URL{a, b}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		defer r.Body.Close()
		record := httptest.NewRecorder()
		hub.ServeHTTP(record, r)
		response := record.Result()
		response.ProtoMajor = 2
		mu.Lock()
		if lost[body[0]] == nil {
			lost[body[0]] = make(map[string]bool)
		}
		drop := !lost[body[0]][r.URL.Host]
		lost[body[0]][r.URL.Host] = true
		mu.Unlock()
		if drop {
			response.Body.Close()
			return nil, io.ErrUnexpectedEOF
		}
		return response, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Open(ctx, "example.org:443")
	if err != nil {
		t.Fatal("lost opens must recover:", err)
	}
	defer stream.Close()
	if _, err := client.request(ctx, stream.token[:], stream.hub, opWrite, 0, 0, payload); err != nil {
		t.Fatal("lost upload ACKs must recover:", err)
	}
	block, err := client.request(ctx, stream.token[:], stream.hub, opRead, 0, 0, nil)
	if err != nil || !bytes.Equal(block.data, payload) {
		t.Fatalf("lost download responses: data=%d err=%v", len(block.data), err)
	}
	if _, err := client.request(ctx, stream.token[:], stream.hub, opFin, 1, 0, nil); err != nil {
		t.Fatal("lost FIN ACKs must recover:", err)
	}
	block, err = client.request(ctx, stream.token[:], stream.hub, opRead, 1, 1, nil)
	if err != nil || !block.eof {
		t.Fatal("download EOF:", err)
	}
	if _, err := client.request(ctx, stream.token[:], stream.hub, opClose, 0, 0, nil); err != nil {
		t.Fatal("lost close ACKs must recover:", err)
	}
	if dials.Load() != 1 {
		t.Fatal("recovery redialed destination:", dials.Load())
	}
	select {
	case got := <-delivered:
		if !bytes.Equal(got, payload) {
			t.Fatal("destination received different data")
		}
	case <-ctx.Done():
		t.Fatal("destination worker retained")
	}
	for _, op := range []byte{opOpen, opWrite, opRead, opFin, opClose} {
		if len(lost[op]) != 2 {
			t.Fatal("did not exercise both entries for operation", op)
		}
	}
}

func TestRequestRecoveryBoundsAndTerminalErrors(t *testing.T) {
	a, _ := url.Parse("https://a.example")
	b, _ := url.Parse("https://b.example")
	for _, test := range []struct {
		name   string
		status int
		err    error
		want   int
	}{
		{"unavailable", 503, nil, 6},
		{"rate-limit", 429, nil, 6},
		{"timeout", 0, context.DeadlineExceeded, 6},
		{"certificate", 0, &tls.CertificateVerificationError{Err: io.ErrUnexpectedEOF}, 1},
		{"tls-alert", 0, tls.AlertError(42), 1},
		{"unauthorized", 403, nil, 1},
		{"different-hub", 409, nil, 1},
		{"closed-session", 410, nil, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			client := &Client{Endpoints: []*url.URL{a, b}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				r.Body.Close()
				if test.err != nil {
					return nil, test.err
				}
				return &http.Response{StatusCode: test.status, ProtoMajor: 2, ContentLength: 0, Body: http.NoBody}, nil
			})}
			if _, err := client.request(context.Background(), make([]byte, 32), "hub", opWrite, 0, 0, []byte("x")); err == nil {
				t.Fatal("request unexpectedly succeeded")
			}
			if calls != test.want {
				t.Fatal("attempt bound:", calls, "want", test.want)
			}
		})
	}
}

func TestRecoveryCancellationStopsBeforeNextSweep(t *testing.T) {
	a, _ := url.Parse("https://a.example")
	b, _ := url.Parse("https://b.example")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int
	client := &Client{Endpoints: []*url.URL{a, b}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		r.Body.Close()
		if calls == 2 {
			cancel()
		}
		return nil, io.ErrUnexpectedEOF
	})}
	if _, err := client.request(ctx, make([]byte, 32), "hub", opWrite, 0, 0, []byte("x")); err != context.Canceled || calls != 2 {
		t.Fatal("cancellation did not stop recovery:", err, calls)
	}
}
