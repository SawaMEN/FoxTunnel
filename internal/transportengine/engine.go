// Package transportengine resolves local FoxTunnel client transport intent.
// It does not change the on-wire protocol or bypass certificate verification.
package transportengine

import (
	"errors"
	"fmt"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
	"github.com/SawaMEN/FoxTunnel/internal/neqo"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
)

// Config is local client policy. It is not serialized into connection links.
// Engine is "legacy" (default) or the opt-in "mozilla".
type Config struct {
	Engine               string
	Transport            string
	TLSBackend           string
	QUICBackend          string
	H3Fallback           string
	QUICHandshakeTimeout time.Duration
	TLSClientProfile     string
	HTTP2ReceiveProfile  string
}

// Plan is a resolved, build-aware selection of the existing native transports.
// A Mozilla plan requires native NSS and uses Neqo only when compiled in.
type Plan struct{ Config }

// Resolve keeps the historical CLI/SDK defaults for legacy mode. Mozilla
// mode selects Neqo/H3 when available, otherwise NSS/H2 for an automatic
// transport. It never substitutes Go TLS or quic-go for Mozilla explicitly.
func Resolve(cfg Config) (Plan, error) {
	switch cfg.Engine {
	case "", "legacy":
		cfg.Engine = "legacy"
		return Plan{Config: cfg}, nil
	case "mozilla":
		return resolveMozilla(cfg)
	default:
		return Plan{}, fmt.Errorf("unknown transport engine %q (choose legacy or mozilla)", cfg.Engine)
	}
}

func resolveMozilla(cfg Config) (Plan, error) {
	if !buildinfo.NSSAvailable {
		return Plan{}, errors.New("Mozilla engine requires a Linux NSS-enabled build; Go TLS fallback is not allowed")
	}
	if cfg.TLSBackend != "" && cfg.TLSBackend != "auto" && cfg.TLSBackend != "nss" {
		return Plan{}, errors.New("Mozilla engine requires NSS TLS; explicit Go TLS is incompatible")
	}
	cfg.TLSBackend = "nss"

	if cfg.Transport == "" || cfg.Transport == "auto" {
		if neqo.Available {
			cfg.Transport = "h3-post"
		} else {
			cfg.Transport = "h2-connect"
		}
	}

	if cfg.Transport == "h3-post" {
		if !neqo.Available {
			return Plan{}, fmt.Errorf("Mozilla HTTP/3 requires the experimental Neqo build (Linux amd64, -tags nss,neqo): %w", neqo.ErrUnavailable)
		}
		if cfg.QUICBackend != "" && cfg.QUICBackend != "auto" && cfg.QUICBackend != "neqo" {
			return Plan{}, errors.New("Mozilla HTTP/3 requires Neqo, not quic-go")
		}
		cfg.QUICBackend = "neqo"
		if cfg.H3Fallback == "" {
			cfg.H3Fallback = "h2"
		}
		if cfg.H3Fallback != "h2" && cfg.H3Fallback != "none" {
			return Plan{}, errors.New("Mozilla H3 fallback must be none or h2")
		}
		// The existing native Neqo adapter owns its QUIC TLS and HTTP/3
		// settings. TCP Firefox profiles cannot be applied to that socket.
		if cfg.TLSClientProfile != "" && cfg.TLSClientProfile != "default" {
			return Plan{}, errors.New("TCP TLS client profile cannot be used with Neqo HTTP/3")
		}
		if cfg.HTTP2ReceiveProfile != "" && cfg.HTTP2ReceiveProfile != "default" {
			return Plan{}, errors.New("HTTP/2 receive profile cannot be used with Neqo HTTP/3")
		}
		cfg.TLSClientProfile = ""
		cfg.HTTP2ReceiveProfile = ""
	} else {
		if cfg.QUICBackend != "" && cfg.QUICBackend != "auto" && cfg.QUICBackend != "quic-go" {
			return Plan{}, errors.New("Neqo QUIC backend requires an HTTP/3 transport")
		}
		if cfg.H3Fallback != "" && cfg.H3Fallback != "none" {
			return Plan{}, errors.New("H3 fallback requires an HTTP/3 transport")
		}
		if cfg.QUICHandshakeTimeout != 0 {
			return Plan{}, errors.New("QUIC handshake timeout requires an HTTP/3 transport")
		}
		cfg.QUICBackend = "quic-go" // Unused by H2/WSS/XHTTP.
		cfg.H3Fallback = "none"
		if cfg.TLSClientProfile == "" || cfg.TLSClientProfile == "default" {
			cfg.TLSClientProfile = nsstls.Firefox158
		}
		switch cfg.Transport {
		case "wss":
			// WSS uses HTTP/1.1 externally; its H2 is carried inside WS.
			if cfg.HTTP2ReceiveProfile != "" && cfg.HTTP2ReceiveProfile != "default" {
				return Plan{}, errors.New("WSS cannot use the outer HTTP/2 receive profile")
			}
			cfg.HTTP2ReceiveProfile = ""
		default:
			if cfg.HTTP2ReceiveProfile == "" || cfg.HTTP2ReceiveProfile == "default" {
				cfg.HTTP2ReceiveProfile = "firefox-158"
			}
		}
	}
	return Plan{Config: cfg}, nil
}

// Apply uses the same order as the original CLI/SDK setters. Trust policy
// is installed before the final transport is used. The NSS/Neqo adapters
// continue to enforce CA, SNI, SPKI, ALPN and request-before-fallback rules.
func (p Plan) Apply(c *tunnel.Client, serverName, pin string) error {
	initialBackend := p.TLSBackend
	if initialBackend == "" {
		initialBackend = "auto"
	}
	// A client cannot select NSS for plain Go H3 before Neqo is enabled.
	if p.QUICBackend == "neqo" && initialBackend == "nss" {
		initialBackend = "auto"
	}
	if err := c.SetTLSBackend(initialBackend); err != nil {
		return err
	}
	if err := c.SetServerIdentity(serverName, pin); err != nil {
		return err
	}
	if err := c.SetTransport(p.Transport); err != nil {
		return err
	}
	if p.H3Fallback != "" && p.H3Fallback != "none" && p.H3Fallback != "h2" {
		return errors.New("H3 fallback must be none or h2")
	}
	if err := c.SetQUICBackend(p.QUICBackend, p.H3Fallback == "h2", p.QUICHandshakeTimeout); err != nil {
		return err
	}
	if p.QUICBackend == "neqo" && p.TLSBackend == "nss" {
		if err := c.SetTLSBackend("nss"); err != nil {
			return err
		}
	}
	if err := c.SetTLSClientProfile(p.TLSClientProfile); err != nil {
		return err
	}
	return c.SetHTTP2ReceiveProfile(p.HTTP2ReceiveProfile)
}
