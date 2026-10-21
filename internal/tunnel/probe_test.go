package tunnel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"
)

type probeRoundTripper func(*http.Request) (*http.Response, error)

func (f probeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func (f probeRoundTripper) CloseIdleConnections()                             {}

type probeBody struct {
	ctx    context.Context
	closed bool
}

func (b *probeBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *probeBody) Close() error {
	if b.ctx.Err() == nil {
		return errors.New("body closed before request cancellation")
	}
	b.closed = true
	return nil
}

func TestTransportProbeMetadataAndCleanup(t *testing.T) {
	for _, test := range []struct {
		name  string
		major int
		err   error
		ok    bool
	}{
		{"h2-redirect", 2, nil, true},
		{"h3-redirect", 3, nil, true},
		{"h1-rejected", 1, nil, false},
		{"response-and-error", 2, errors.New("private-peer-error"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			origin, _ := url.Parse("https://proxy.invalid")
			var body *probeBody
			calls := 0
			c := &Client{ServerURL: origin, Username: "private-user", Password: "private-password", transport: probeRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodHead || r.URL.String() != "https://proxy.invalid/" || len(r.Header) != 0 || r.Body != nil {
					t.Fatal("probe included credentials, target or payload")
				}
				body = &probeBody{ctx: r.Context()}
				return &http.Response{ProtoMajor: test.major, StatusCode: 302, Header: http.Header{"Location": []string{"https://redirect.invalid/private"}}, Body: body}, test.err
			})}
			result, err := c.ProbeTransport(context.Background())
			if (err == nil) != test.ok || calls != 1 || !body.closed {
				t.Fatalf("probe result/cleanup mismatch: %+v, %v", result, err)
			}
			if test.ok && (result.HTTPMajor != test.major || result.HTTPStatus != 302) {
				t.Fatal("probe lost HTTP metadata")
			}
		})
	}
}

func TestTransportProbeCanceledBeforeIO(t *testing.T) {
	origin, _ := url.Parse("https://proxy.invalid")
	c := &Client{ServerURL: origin, transport: probeRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Error("canceled probe performed network I/O")
		return nil, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ProbeTransport(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("probe ignored cancellation")
	}
}
