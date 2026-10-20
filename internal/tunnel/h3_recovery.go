package tunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
)

// h3Pool is one connection cache. quic-go's own idle counter covers RoundTrip,
// not the lifetime of a duplex response body, so we track that lifetime here.
type h3Pool interface {
	http.RoundTripper
	Close() error
}

type h3Generation struct {
	pool    h3Pool
	refs    int
	retired bool
}

// h3RecoveryTransport retires an unresponsive pool after a setup deadline.
// Only future requests use a fresh pool: this never replays a submitted request
// or closes another request's live response body.
type h3RecoveryTransport struct {
	mu          sync.Mutex
	newPool     func() h3Pool
	current     *h3Generation
	generations map[*h3Generation]struct{}
}

func (t *h3RecoveryTransport) acquire() *h3Generation {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current == nil {
		t.current = &h3Generation{pool: t.newPool()}
		if t.generations == nil {
			t.generations = make(map[*h3Generation]struct{})
		}
		t.generations[t.current] = struct{}{}
	}
	t.current.refs++
	return t.current
}

func (t *h3RecoveryTransport) release(g *h3Generation, retire bool) {
	t.mu.Lock()
	if retire {
		g.retired = true
		if t.current == g {
			t.current = nil
		}
	}
	g.refs--
	closePool := g.retired && g.refs == 0
	if closePool {
		delete(t.generations, g)
	}
	t.mu.Unlock()
	if closePool {
		_ = g.pool.Close()
	}
}

func (t *h3RecoveryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	g := t.acquire()
	response, err := g.pool.RoundTrip(req)
	if err != nil {
		retire := response == nil && errors.Is(context.Cause(req.Context()), context.DeadlineExceeded)
		t.release(g, retire)
		return response, err
	}
	if response.Body == nil {
		t.release(g, false)
		return response, nil
	}
	response.Body = &h3ResponseBody{ReadCloser: response.Body, release: func() { t.release(g, false) }}
	return response, nil
}

func (t *h3RecoveryTransport) CloseIdleConnections() {
	var pools []h3Pool
	t.mu.Lock()
	t.current = nil
	for g := range t.generations {
		g.retired = true
		if g.refs == 0 {
			delete(t.generations, g)
			pools = append(pools, g.pool)
		}
	}
	t.mu.Unlock()
	for _, pool := range pools {
		_ = pool.Close()
	}
}

type h3ResponseBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
	err     error
}

func (b *h3ResponseBody) Close() error {
	b.once.Do(func() { b.err = b.ReadCloser.Close(); b.release() })
	return b.err
}
