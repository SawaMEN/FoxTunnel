//go:build !nss || !cgo || !linux

package nsstls

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/SawaMEN/FoxTunnel/internal/h2profile"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"net"
	"net/http"
)

type Transport interface {
	http.RoundTripper
	CloseIdleConnections()
}

func NewTransport(*tls.Config) (Transport, error) {
	return nil, errors.New(i18n.Text("NSS backend unavailable: build on Linux with CGO_ENABLED=1 and -tags nss (NSS/NSPR development packages required)"))
}

func DialTLSContext(context.Context, string, string, *tls.Config) (net.Conn, error) {
	return nil, i18n.Error("NSS backend unavailable: build on Linux with CGO_ENABLED=1 and -tags nss (NSS/NSPR development packages required)")
}

func NewTransportWithProfile(config *tls.Config, profile string) (Transport, error) {
	if err := h2profile.Validate(profile); err != nil {
		return nil, err
	}
	return NewTransport(config)
}
