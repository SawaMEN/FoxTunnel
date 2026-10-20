package tunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type fakeH3Pool struct {
	roundTrip func(*http.Request) (*http.Response, error)
	calls     atomic.Int64
	closed    atomic.Int64
}

func (p *fakeH3Pool) RoundTrip(r *http.Request) (*http.Response, error) {
	p.calls.Add(1)
	return p.roundTrip(r)
}
func (p *fakeH3Pool) Close() error { p.closed.Add(1); return nil }

func TestH3DeadlineRetiresPoolWithoutReplayOrClosingLiveBody(t *testing.T) {
	var pools []*fakeH3Pool
	var deadline context.CancelCauseFunc
	transport := &h3RecoveryTransport{newPool: func() h3Pool {
		pool := &fakeH3Pool{roundTrip: func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/timeout" {
				deadline(context.DeadlineExceeded)
				return nil, context.Canceled
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("live"))}, nil
		}}
		pools = append(pools, pool)
		return pool
	}}
	defer transport.CloseIdleConnections()
	hold, _ := http.NewRequest("GET", "https://localhost/hold", nil)
	active, err := transport.RoundTrip(hold)
	if err != nil {
		t.Fatal(err)
	}
	// EOF alone must not release a duplex response: its upload may still run.
	io.Copy(io.Discard, active.Body)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	deadline = cancel
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/timeout", nil)
	if _, err := transport.RoundTrip(request); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(pools) != 1 || pools[0].calls.Load() != 2 || pools[0].closed.Load() != 0 {
		t.Fatal("timed out request replayed or active body closed")
	}
	next, err := transport.RoundTrip(hold)
	if err != nil {
		t.Fatal(err)
	}
	if len(pools) != 2 || pools[1].calls.Load() != 1 {
		t.Fatal("next request reused failed generation")
	}
	next.Body.Close()
	active.Body.Close()
	active.Body.Close()
	if pools[0].closed.Load() != 1 {
		t.Fatal("retired generation did not close exactly once")
	}
	transport.CloseIdleConnections()
	if pools[1].closed.Load() != 1 || len(transport.generations) != 0 {
		t.Fatal("idle generation leaked")
	}
}

func TestH3CallerCancellationAndHTTPRejectionDoNotRetirePool(t *testing.T) {
	for _, kind := range []string{"cancel", "http"} {
		t.Run(kind, func(t *testing.T) {
			var cancel context.CancelCauseFunc
			pool := &fakeH3Pool{roundTrip: func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/fail" {
					if kind == "cancel" {
						cancel(context.Canceled)
						return nil, context.Canceled
					}
					cancel(context.DeadlineExceeded)
					return &http.Response{StatusCode: 403, Body: http.NoBody}, nil
				}
				return &http.Response{Body: http.NoBody}, nil
			}}
			created := 0
			transport := &h3RecoveryTransport{newPool: func() h3Pool { created++; return pool }}
			defer transport.CloseIdleConnections()
			ctx, abort := context.WithCancelCause(context.Background())
			defer abort(nil)
			cancel = abort
			request, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost/fail", nil)
			response, _ := transport.RoundTrip(request)
			if response != nil {
				response.Body.Close()
			}
			next, _ := http.NewRequest("GET", "https://localhost/next", nil)
			response, err := transport.RoundTrip(next)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if created != 1 || pool.closed.Load() != 0 || pool.calls.Load() != 2 {
				t.Fatal("cancel/HTTP error changed generation or retried request")
			}
		})
	}
}

func TestH3AlreadyCancelledRequestDoesNotCreatePool(t *testing.T) {
	transport := &h3RecoveryTransport{newPool: func() h3Pool { t.Fatal("created pool for cancelled request"); return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://localhost", nil)
	if _, err := transport.RoundTrip(request); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
