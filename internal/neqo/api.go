// Package neqo adapts the pinned Mozilla HTTP/3 client. It is never quic-go.
package neqo

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"time"
)

const Version = "0.33.0"
const Revision = "1ec4c2a3ccd7ada264112d1b70b070381557d844"

var ErrUnavailable = errors.New("Neqo unavailable: build on Linux amd64 with CGO and -tags nss,neqo after building the pinned Rust bridge")
var ErrCapacity = errors.New("Neqo connection or stream capacity reached")
var errProtocol = errors.New("Neqo TLS/HTTP3 protocol failure")
var errClosed = errors.New("Neqo stream closed")
var errDraining = errors.New("Neqo HTTP/3 connection draining before request creation")

type Config struct {
	TLS              *tls.Config
	HandshakeTimeout time.Duration
}
type Transport interface {
	http.RoundTripper
	Probe(context.Context, *url.URL) error
	CloseIdleConnections()
}

// ReachabilityError is emitted only before HTTP stream creation. TLS trust,
// configuration, malformed replies and HTTP errors are never classified this way.
type ReachabilityError struct{ Err error }

func (e *ReachabilityError) Error() string { return "Neqo handshake unreachable" }
func (e *ReachabilityError) Unwrap() error { return e.Err }
