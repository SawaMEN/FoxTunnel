//go:build !nss || !cgo || !linux

package nsstls

import (
	"crypto/tls"
	"errors"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"net/http"
)

type Transport interface {
	http.RoundTripper
	CloseIdleConnections()
}

func NewTransport(*tls.Config) (Transport, error) {
	return nil, errors.New(i18n.Text("NSS backend unavailable: build on Linux with CGO_ENABLED=1 and -tags nss (NSS/NSPR development packages required)"))
}
