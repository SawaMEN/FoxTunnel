//go:build !nss || !cgo || !linux

package nsstls

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/SawaMEN/VetroffProxy/internal/h2profile"
	"github.com/SawaMEN/VetroffProxy/internal/i18n"
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
	return NewTransportWithProfiles(config, profile, "")
}
func NewTransportWithProfiles(config *tls.Config, profile, clientProfile string) (Transport, error) {
	if err := h2profile.Validate(profile); err != nil {
		return nil, err
	}
	if err := ValidateClientProfile(clientProfile); err != nil {
		return nil, err
	}
	return NewTransport(config)
}

func DialTLSContextWithProfile(ctx context.Context, network, addr string, config *tls.Config, profile string) (net.Conn, error) {
	if err := ValidateClientProfile(profile); err != nil {
		return nil, err
	}
	return DialTLSContext(ctx, network, addr, config)
}
