package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/SawaMEN/FoxTunnel/internal/i18n"
)

// TransportProbe describes a response over the configured carrier, not an
// authenticated destination tunnel. WSS/XHTTP report their inner HTTP version.
type TransportProbe struct {
	HTTPMajor  int
	HTTPStatus int
}

// ProbeTransport makes one HEAD request to the configured origin with the
// selected TLS/QUIC/carrier stack. It never follows redirects or dials a target.
// The inner HEAD has no credentials; authenticated outer WSS/XHTTP carriers
// retain their usual verified-TLS authentication requirements.
func (c *Client) ProbeTransport(ctx context.Context) (TransportProbe, error) {
	if err := ctx.Err(); err != nil {
		return TransportProbe{}, err
	}
	call, cancel := context.WithCancel(ctx)
	u := *c.ServerURL
	u.Path, u.RawPath, u.RawQuery, u.Fragment = "/", "", "", ""
	req, err := http.NewRequestWithContext(call, http.MethodHead, u.String(), nil)
	if err != nil {
		cancel()
		return TransportProbe{}, err
	}
	resp, err := c.transport.RoundTrip(req)
	// Cancel before closing a duplex body, whose teardown can join a writer.
	cancel()
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return TransportProbe{}, err
	}
	if resp == nil || (resp.ProtoMajor != 2 && resp.ProtoMajor != 3) {
		return TransportProbe{}, errors.New("transport probe requires HTTP/2 or HTTP/3")
	}
	return TransportProbe{HTTPMajor: resp.ProtoMajor, HTTPStatus: resp.StatusCode}, nil
}

// ConnectResponseError preserves status metadata without retaining any target,
// credentials, response headers or peer-controlled response body.
type ConnectResponseError struct {
	HTTPMajor  int
	HTTPStatus int
}

func (e *ConnectResponseError) Error() string {
	return fmt.Sprintf(i18n.Text("CONNECT rejected (HTTP/%d status %d)"), e.HTTPMajor, e.HTTPStatus)
}
