package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/neqo"
)

type fakeNeqo struct {
	probe func(context.Context, *url.URL) error
	round func(*http.Request) (*http.Response, error)
}

func (f fakeNeqo) Probe(ctx context.Context, u *url.URL) error       { return f.probe(ctx, u) }
func (f fakeNeqo) RoundTrip(r *http.Request) (*http.Response, error) { return f.round(r) }
func (f fakeNeqo) CloseIdleConnections()                             {}

type fakeH2 struct {
	round func(*http.Request) (*http.Response, error)
}

func (f fakeH2) RoundTrip(r *http.Request) (*http.Response, error) { return f.round(r) }
func (f fakeH2) CloseIdleConnections()                             {}
func TestQUICFallbackOnlyBeforeRequestAndOnlyNetwork(t *testing.T) {
	for _, name := range []string{"network", "trust", "protocol", "canceled", "post-start", "http-status"} {
		t.Run(name, func(t *testing.T) {
			h2Calls, h3Calls := 0, 0
			probe := func(context.Context, *url.URL) error {
				switch name {
				case "network":
					return &neqo.ReachabilityError{Err: context.DeadlineExceeded}
				case "trust":
					return &tls.CertificateVerificationError{Err: errors.New("untrusted")}
				case "protocol":
					return errors.New("ALPN mismatch")
				case "canceled":
					return context.Canceled
				}
				return nil
			}
			h3 := fakeNeqo{probe: probe, round: func(r *http.Request) (*http.Response, error) {
				h3Calls++
				if name == "post-start" {
					return nil, &neqo.ReachabilityError{Err: io.ErrUnexpectedEOF}
				}
				return &http.Response{StatusCode: 403, Body: http.NoBody}, nil
			}}
			h2 := fakeH2{round: func(r *http.Request) (*http.Response, error) {
				h2Calls++
				data, _ := io.ReadAll(r.Body)
				if string(data) != "one copy" {
					t.Error("request body consumed before fallback")
				}
				return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
			}}
			transport := &neqoFallbackTransport{h3: h3, h2: h2, until: make(map[string]time.Time)}
			req, _ := http.NewRequest("POST", "https://example.org", strings.NewReader("one copy"))
			resp, err := transport.RoundTrip(req)
			if name == "network" {
				if err != nil || resp.StatusCode != 200 || h2Calls != 1 || h3Calls != 0 {
					t.Fatal("network fallback", err, h2Calls, h3Calls)
				}
			} else {
				if h2Calls != 0 {
					t.Fatal("unsafe fallback", name)
				}
				if name == "http-status" && (err != nil || resp.StatusCode != 403) {
					t.Fatal("HTTP failure changed", err)
				}
			}
		})
	}
}
func TestQUICSettingsValidationRollback(t *testing.T) {
	c, _ := testClient(t, http.NotFoundHandler())
	old := c.transport
	for _, args := range []struct {
		backend  string
		fallback bool
		timeout  time.Duration
	}{{"unknown", false, 0}, {"quic-go", true, 0}, {"neqo", false, time.Second}, {"quic-go", false, -1}} {
		if err := c.SetQUICBackend(args.backend, args.fallback, args.timeout); err == nil || c.transport != old || c.quic != (quicSettings{}) {
			t.Fatal("invalid QUIC settings changed transport", args, err)
		}
	}
	if err := c.SetTransport("h3-post"); err != nil {
		t.Fatal(err)
	}
	if !neqo.Available {
		old = c.transport
		if err := c.SetQUICBackend("neqo", false, time.Second); !errors.Is(err, neqo.ErrUnavailable) || c.transport != old || c.quic != (quicSettings{}) {
			t.Fatal("missing backend did not fail closed", err)
		}
	}
}
