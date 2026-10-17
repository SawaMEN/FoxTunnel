//go:build !nss || !cgo || !linux

package nsstls

import (
	"crypto/tls"
	"errors"
	"net/http"
)

type Transport interface {
	http.RoundTripper
	CloseIdleConnections()
}

func NewTransport(*tls.Config) (Transport, error) {
	return nil, errors.New("NSS backend unavailable: build on Linux with CGO_ENABLED=1 and -tags nss (NSS/NSPR development packages required)")
}
