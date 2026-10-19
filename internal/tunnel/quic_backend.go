package tunnel

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/neqo"
)

type quicSettings struct {
	backend  string
	fallback bool
	timeout  time.Duration
}

// SetQUICBackend is a local opt-in for h3-post. Configure after SetTransport and
// before bond/Serve. Default remains quic-go; explicit Neqo never selects it.
func (c *Client) SetQUICBackend(backend string, h2Fallback bool, timeout time.Duration) error {
	if backend == "" {
		backend = "quic-go"
	}
	if backend != "quic-go" && backend != "neqo" {
		return errors.New("QUIC backend must be quic-go or neqo")
	}
	if c.bondClient != nil || c.bondDiscovery != nil {
		return errors.New("configure QUIC before enabling bond")
	}
	if timeout < 0 || timeout > 10*time.Second || (timeout > 0 && timeout < 100*time.Millisecond) {
		return errors.New("QUIC handshake timeout must be 100ms through 10s")
	}
	if backend == "quic-go" && (h2Fallback || timeout != 0) {
		return errors.New("QUIC fallback/timeout options require Neqo")
	}
	if backend == "neqo" && c.nativeTransport != "h3-post" {
		return errors.New("Neqo requires h3-post")
	}
	if backend == "neqo" && c.backend == "go" {
		return errors.New("Neqo uses NSS; TLS backend go is incompatible")
	}
	old := c.quic
	c.quic = quicSettings{backend: backend, fallback: h2Fallback, timeout: timeout}
	if err := c.SetTLSBackend(c.backend); err != nil {
		c.quic = old
		return err
	}
	return nil
}

// One probe is shared by simultaneous requests to the same origin. Waiting
// callers keep their own contexts and their request bodies untouched.
type neqoProbe struct {
	done       chan struct{}
	err        error
	useH2      bool
	retry      bool // owner request canceled or network changed mid-probe
	generation uint64
}

type neqoFallbackTransport struct {
	h3         neqo.Transport
	h2         tlsTransport
	mu         sync.Mutex
	until      map[string]time.Time
	probes     map[string]*neqoProbe
	generation uint64
}

const h3RetryAfter = 30 * time.Second
const maxReachabilityOrigins = 8

// selection occurs entirely before submitting a request to either transport.
// Only Neqo's typed pre-request ReachabilityError permits the H2 path; trust,
// authentication, configuration, protocol and HTTP errors never authorize it.
func (t *neqoFallbackTransport) selectTransport(ctx context.Context, target *url.URL) (bool, error) {
	origin := target.Scheme + "://" + target.Host
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		t.mu.Lock()
		if time.Now().Before(t.until[origin]) {
			t.mu.Unlock()
			return true, nil
		}
		if existing := t.probes[origin]; existing != nil {
			t.mu.Unlock()
			select {
			case <-existing.done:
				// A network event may arrive after a completed probe but
				// before this waiter observes it. Discard that result too.
				t.mu.Lock()
				stale := existing.retry || t.generation != existing.generation
				t.mu.Unlock()
				if stale {
					continue
				}
				return existing.useH2, existing.err
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}
		if t.probes == nil {
			t.probes = make(map[string]*neqoProbe)
		}
		probe := &neqoProbe{
			done: make(chan struct{}),
			generation: t.generation,
		}
		t.probes[origin] = probe
		t.mu.Unlock()

		// No HTTP stream, credentials or request body have been sent.
		err := t.h3.Probe(ctx, target)
		var unreachable *neqo.ReachabilityError
		reachableFailure := errors.As(err, &unreachable)
		canceled := ctx.Err() != nil

		t.mu.Lock()
		if t.probes[origin] == probe {
			delete(t.probes, origin)
		}
		if t.generation != probe.generation || canceled {
			probe.retry = true
		} else if reachableFailure {
			probe.useH2 = true
			if t.until == nil {
				t.until = make(map[string]time.Time)
			}
			// Bound entries, favoring the earliest expiry on eviction.
			if len(t.until) >= maxReachabilityOrigins {
				var evict string
				var earliest time.Time
				for key, expiry := range t.until {
					if evict == "" || expiry.Before(earliest) {
						evict, earliest = key, expiry
					}
				}
				delete(t.until, evict)
			}
			t.until[origin] = time.Now().Add(h3RetryAfter)
		} else {
			probe.err = err
			// A successful probe restores H3 preference for the origin.
			if err == nil {
				delete(t.until, origin)
			}
		}
		close(probe.done)
		t.mu.Unlock()

		if canceled {
			return false, ctx.Err()
		}
		if probe.retry {
			continue
		}
		if probe.useH2 {
			// Only close unused QUIC engines. Existing active HTTP/3
			// streams to this or other origins continue unchanged.
			t.h3.CloseIdleConnections()
		}
		return probe.useH2, probe.err
	}
}

func (t *neqoFallbackTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// The original HTTP request and its body are never replayed or cloned.
	// After selecting a backend, all errors and HTTP statuses are terminal
	// for this request (including failures after H3 stream creation).
	useH2, err := t.selectTransport(r.Context(), r.URL)
	if err != nil {
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, err
	}
	if useH2 {
		return t.h2.RoundTrip(r)
	}
	return t.h3.RoundTrip(r)
}

// NetworkChanged is invoked by a platform integrator after an observed
// connectivity change. A generation prevents old in-flight probes from
// poisoning the new network's reachability cache.
func (t *neqoFallbackTransport) NetworkChanged() {
	t.mu.Lock()
	clear(t.until)
	t.generation++
	t.mu.Unlock()
	// Do not tear down active streams: close only idle connections.
	t.h3.CloseIdleConnections()
	t.h2.CloseIdleConnections()
}

func (t *neqoFallbackTransport) CloseIdleConnections() {
	t.h3.CloseIdleConnections()
	t.h2.CloseIdleConnections()
}
