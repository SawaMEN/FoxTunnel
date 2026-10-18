// Package tlsidentity validates public server identity settings. A pin adds to,
// and never replaces, ordinary certificate chain/hostname verification.
package tlsidentity

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"strings"
)

type Policy struct {
	SNI       string `json:"sni,omitempty"`
	PinSHA256 string `json:"pin_sha256,omitempty"`
}

var ErrInvalid = errors.New("invalid TLS identity settings")

func Normalize(sni, pin string) (Policy, error) {
	sni = strings.ToLower(sni)
	if sni != "" {
		if len(sni) > 253 || net.ParseIP(sni) != nil {
			return Policy{}, ErrInvalid
		}
		for _, label := range strings.Split(sni, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Policy{}, ErrInvalid
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return Policy{}, ErrInvalid
				}
			}
		}
	}
	if pin != "" {
		if !strings.HasPrefix(pin, "sha256/") {
			return Policy{}, ErrInvalid
		}
		b, err := base64.StdEncoding.Strict().DecodeString(strings.TrimPrefix(pin, "sha256/"))
		if err != nil || len(b) != sha256.Size || "sha256/"+base64.StdEncoding.EncodeToString(b) != pin {
			return Policy{}, ErrInvalid
		}
	}
	return Policy{SNI: sni, PinSHA256: pin}, nil
}

func Pin(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(digest[:])
}

func (p Policy) Apply(config *tls.Config) {
	if p.SNI != "" {
		config.ServerName = p.SNI
	}
	if p.PinSHA256 == "" {
		return
	}
	previous := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if previous != nil {
			if err := previous(state); err != nil {
				return err
			}
		}
		if len(state.PeerCertificates) == 0 || subtle.ConstantTimeCompare([]byte(Pin(state.PeerCertificates[0])), []byte(p.PinSHA256)) != 1 {
			return &tls.CertificateVerificationError{UnverifiedCertificates: state.PeerCertificates, Err: errors.New("server public key does not match pin")}
		}
		return nil
	}
}
