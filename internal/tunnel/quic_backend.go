package tunnel

import (
	"errors"
	"net/http"
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

type neqoFallbackTransport struct {
	h3    neqo.Transport
	h2    tlsTransport
	mu    sync.Mutex
	until map[string]time.Time
}

func (t *neqoFallbackTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	origin := r.URL.Scheme + "://" + r.URL.Host
	t.mu.Lock()
	fallback := time.Now().Before(t.until[origin])
	t.mu.Unlock()
	if !fallback {
		err := t.h3.Probe(r.Context(), r.URL)
		if err == nil {
			return t.h3.RoundTrip(r)
		}
		if r.Context().Err() != nil {
			if r.Body != nil {
				r.Body.Close()
			}
			return nil, r.Context().Err()
		}
		var unreachable *neqo.ReachabilityError
		if !errors.As(err, &unreachable) {
			if r.Body != nil {
				r.Body.Close()
			}
			return nil, err
		}
		t.mu.Lock()
		if len(t.until) >= 8 {
			clear(t.until)
		}
		t.until[origin] = time.Now().Add(30 * time.Second)
		t.mu.Unlock()
		t.h3.CloseIdleConnections()
	}
	// No HTTP request has been created in Neqo yet. The original body is untouched;
	// no replayable-body assumption or fallback after an HTTP status is allowed.
	return t.h2.RoundTrip(r)
}
func (t *neqoFallbackTransport) CloseIdleConnections() {
	t.h3.CloseIdleConnections()
	t.h2.CloseIdleConnections()
}
