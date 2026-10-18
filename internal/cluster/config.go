// Package cluster defines bounded coordinator-issued bond topology snapshots.
package cluster

import (
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/SawaMEN/FoxTunnel/internal/safejson"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

const Path = "/.well-known/foxtunnel-cluster-v1"
const MaxBytes = 16 << 10

type Node struct {
	URL       string `json:"url"`
	Weight    int    `json:"weight"`
	Disabled  bool   `json:"disabled,omitempty"`
	SNI       string `json:"sni,omitempty"`
	PinSHA256 string `json:"pin_sha256,omitempty"`
}
type Config struct {
	Version int    `json:"v"`
	Nodes   []Node `json:"nodes"`
}
type Manifest struct {
	Version  int    `json:"v"`
	HubID    string `json:"hub_id"`
	ValidFor int    `json:"valid_for"`
	Nodes    []Node `json:"nodes"`
}

var ErrInvalid = errors.New("invalid cluster configuration")

// Origin accepts only a root HTTPS origin, never a redirect, path or credential.
func Origin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.HasSuffix(u.Host, ":") || strings.ContainsAny(u.Host, "\x00\r\n\t ") {
		return nil, ErrInvalid
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, ErrInvalid
		}
	}
	u.Path = ""
	return u, nil
}

func validateNodes(nodes []Node) error {
	if len(nodes) < 1 || len(nodes) > 8 {
		return ErrInvalid
	}
	seen := make(map[string]bool)
	active := 0
	for i := range nodes {
		n := &nodes[i]
		u, err := Origin(n.URL)
		if err != nil {
			return ErrInvalid
		}
		policy, err := tlsidentity.Normalize(n.SNI, n.PinSHA256)
		if err != nil {
			return ErrInvalid
		}
		n.SNI, n.PinSHA256 = policy.SNI, policy.PinSHA256
		port := u.Port()
		if port == "" {
			port = "443"
		}
		p, _ := strconv.Atoi(port)
		key := net.JoinHostPort(strings.ToLower(u.Hostname()), strconv.Itoa(p))
		if seen[key] || n.Weight < 1 || n.Weight > 100 {
			return ErrInvalid
		}
		seen[key] = true
		n.URL = u.String()
		if !n.Disabled {
			active++
		}
	}
	if active == 0 {
		return ErrInvalid
	}
	return nil
}

func DecodeConfig(r io.Reader) (Config, error) {
	var c Config
	if strict(r, &c) != nil || c.Version != 1 || validateNodes(c.Nodes) != nil {
		return Config{}, ErrInvalid
	}
	return c, nil
}
func DecodeManifest(r io.Reader) (Manifest, error) {
	var m Manifest
	if strict(r, &m) != nil || m.Version != 1 || m.ValidFor < 15 || m.ValidFor > 300 || validateNodes(m.Nodes) != nil {
		return Manifest{}, ErrInvalid
	}
	id, err := hex.DecodeString(m.HubID)
	if err != nil || len(id) != 32 || hex.EncodeToString(id) != m.HubID {
		return Manifest{}, ErrInvalid
	}
	for _, n := range m.Nodes {
		if n.Disabled {
			return Manifest{}, ErrInvalid
		}
	}
	return m, nil
}

func strict(r io.Reader, out any) error {
	return safejson.Decode(r, MaxBytes, out)
}
