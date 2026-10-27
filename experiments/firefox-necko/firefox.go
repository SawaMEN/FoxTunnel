// Package firefox runs a separate, real Gecko/Necko networking process.
// Unlike the NSS/Neqo adapters, it does not implement HTTP framing in Go.
package firefox

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/idna"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/authheader"
	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/h2profile"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"github.com/SawaMEN/FoxTunnel/internal/safejson"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

//go:embed client.js
var clientScript []byte

// Config selects native Necko policy in the dedicated helper. Server identity
// applies to the configured primary origin; other origins retain their own identity.
type Config struct {
	NodePolicies           map[string]tlsidentity.Policy `json:"node_policies,omitempty"`
	ServerName             string                        `json:"server_name,omitempty"`
	SPKIPin                string                        `json:"spki_pin,omitempty"`
	TLSClientProfile       string                        `json:"tls_client_profile,omitempty"`
	HTTP2ReceiveProfile    string                        `json:"http2_receive_profile,omitempty"`
	SOCKSToken             string                        `json:"-"` // Private authenticated IPC; not accepted in user JSON.
	Server                 string                        `json:"server"`
	Username               string                        `json:"username"`
	Password               string                        `json:"password"`
	Transport              string                        `json:"transport"`
	Listen                 string                        `json:"listen"`
	CACert                 string                        `json:"ca_cert,omitempty"`
	MaxConnections         int                           `json:"max_connections,omitempty"`
	ConnectTimeoutMS       int                           `json:"connect_timeout_ms,omitempty"`
	IdleTimeoutMS          int                           `json:"idle_timeout_ms,omitempty"`
	DrainTimeoutMS         int                           `json:"drain_timeout_ms,omitempty"`
	MaxRetainedConnections int                           `json:"max_retained_connections,omitempty"`
	StatsIntervalMS        int                           `json:"stats_interval_ms,omitempty"`
}

func (c Config) normalize() (Config, error) {
	u, err := cluster.Origin(c.Server)
	if err != nil {
		return c, errors.New("Firefox requires an HTTPS proxy origin")
	}
	c.Server = u.String()
	policy, err := tlsidentity.Normalize(c.ServerName, c.SPKIPin)
	if err != nil {
		return c, err
	}
	c.ServerName, c.SPKIPin = policy.SNI, policy.PinSHA256
	if len(c.NodePolicies) != 0 {
		if len(c.NodePolicies) > 8 || c.ServerName != "" || c.SPKIPin != "" {
			return c, errors.New("per-node policies require explicit pinned origins without a primary override")
		}
		nodes := make(map[string]tlsidentity.Policy, len(c.NodePolicies))
		for origin, nodePolicy := range c.NodePolicies {
			endpoint, e := cluster.Origin(origin)
			if e != nil {
				return c, errors.New("invalid native node policy origin")
			}
			key, e := nativeOriginKey(endpoint)
			if e != nil {
				return c, e
			}
			origin = "https://" + key
			validated, e := tlsidentity.Normalize(nodePolicy.SNI, nodePolicy.PinSHA256)
			if e != nil || validated.PinSHA256 == "" {
				return c, errors.New("native node policy requires a valid SPKI pin")
			}
			if _, duplicate := nodes[origin]; duplicate {
				return c, errors.New("duplicate native node policy origin")
			}
			nodes[origin] = validated
		}
		primary, e := nativeOriginKey(u)
		if e != nil {
			return c, e
		}
		if _, ok := nodes["https://"+primary]; !ok {
			return c, errors.New("missing primary native node identity")
		}
		c.NodePolicies = nodes
	}

	if !authheader.ValidCredentials(c.Username, c.Password) {
		return c, errors.New("Firefox requires valid proxy credentials")
	}
	if c.Transport == "" {
		c.Transport = "h2-connect"
	}
	if c.Transport != "h2-connect" && c.Transport != "h3-connect" {
		return c, errors.New("Firefox transport must be h2-connect or h3-connect")
	}
	if err := ValidateProfiles(c.Transport, c.TLSClientProfile, c.HTTP2ReceiveProfile); err != nil {
		return c, err
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:1080"
	}
	host, port, err := net.SplitHostPort(c.Listen)
	n, portErr := strconv.Atoi(port)
	// A numeric loopback address prevents accidental public exposure or DNS
	// rebinding. The initial Necko client intentionally has no LAN mode.
	ip := net.ParseIP(host)
	if err != nil || portErr != nil || n < 0 || n > 65535 || ip == nil || !ip.IsLoopback() {
		return c, errors.New("Firefox SOCKS listener must be a numeric loopback address")
	}
	// nsIServerSocket.init listens on IPv4 loopback; do not accept a setting
	// the helper would silently ignore.
	if host != "127.0.0.1" {
		return c, errors.New("Firefox currently supports 127.0.0.1 only")
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 256
	}
	if c.MaxConnections < 1 || c.MaxConnections > 4096 {
		return c, errors.New("invalid Firefox connection limit")
	}
	if c.ConnectTimeoutMS == 0 {
		c.ConnectTimeoutMS = 15000
	}
	if c.ConnectTimeoutMS < 100 || c.ConnectTimeoutMS > 120000 {
		return c, errors.New("invalid Firefox setup timeout")
	}
	if c.IdleTimeoutMS == 0 {
		c.IdleTimeoutMS = 300000
	}
	if c.DrainTimeoutMS == 0 {
		c.DrainTimeoutMS = 30000
	}
	if c.MaxRetainedConnections == 0 {
		c.MaxRetainedConnections = min(c.MaxConnections*4, 4096)
	}
	if c.IdleTimeoutMS < 100 || c.IdleTimeoutMS > 86400000 || c.DrainTimeoutMS < 100 || c.DrainTimeoutMS > 120000 || c.MaxRetainedConnections < c.MaxConnections || c.MaxRetainedConnections > 16384 || (c.StatsIntervalMS != 0 && (c.StatsIntervalMS < 100 || c.StatsIntervalMS > 60000)) {
		return c, errors.New("invalid Firefox lifetime or metrics limits")
	}
	return c, nil
}

func nativeOriginKey(u *url.URL) (string, error) {
	host := strings.ToLower(u.Hostname())
	if ip, e := netip.ParseAddr(host); e == nil {
		host = ip.String()
	} else {
		var e error
		host, e = idna.Lookup.ToASCII(host)
		if e != nil {
			return "", errors.New("invalid native origin hostname")
		}
	}
	port := 443
	if u.Port() != "" {
		port, _ = strconv.Atoi(u.Port())
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// ValidateProfiles rejects incompatible TCP-specific presets on QUIC.
func ValidateProfiles(transport, tlsProfile, receiveProfile string) error {
	if err := nsstls.ValidateClientProfile(tlsProfile); err != nil {
		return err
	}
	if err := h2profile.Validate(receiveProfile); err != nil {
		return err
	}
	if (transport == "h3-connect" || transport == "h3-post") && (tlsProfile == nsstls.Firefox158 || receiveProfile == h2profile.Firefox158) {
		return errors.New("TCP TLS and HTTP/2 receive profiles cannot be applied to native HTTP/3")
	}
	return nil
}

// ReadConfig rejects unknown options rather than silently dropping trust policy.
// Parsing errors never echo credentials from the input.
func ReadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, errors.New("cannot open Firefox configuration")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return Config{}, errors.New("invalid Firefox configuration")
	}
	var c Config
	if safejson.Decode(bytes.NewReader(data), 1<<20, &c) != nil {
		return Config{}, errors.New("invalid Firefox configuration")
	}
	return c.normalize()
}

type runtimeConfig struct {
	NodePolicies           map[string]tlsidentity.Policy `json:"node_policies,omitempty"`
	ServerName             string                        `json:"server_name,omitempty"`
	SPKIPin                string                        `json:"pin_sha256,omitempty"`
	TLSClientProfile       string                        `json:"tls_client_profile,omitempty"`
	HTTP2ReceiveProfile    string                        `json:"http2_receive_profile,omitempty"`
	SOCKSToken             string                        `json:"socks_token,omitempty"`
	ProxyHost              string                        `json:"proxy_host"`
	ProxyPort              int                           `json:"proxy_port"`
	Authorization          string                        `json:"authorization"`
	Transport              string                        `json:"transport"`
	ListenPort             int                           `json:"listen_port"`
	MaxConnections         int                           `json:"max_connections"`
	ConnectTimeoutMS       int                           `json:"connect_timeout_ms"`
	CAPEM                  string                        `json:"ca_pem"`
	IdleTimeoutMS          int                           `json:"idle_timeout_ms"`
	DrainTimeoutMS         int                           `json:"drain_timeout_ms"`
	MaxRetainedConnections int                           `json:"max_retained_connections"`
	StatsIntervalMS        int                           `json:"stats_interval_ms"`
}

// Run owns a fresh private profile and helper process. Credentials never appear
// in argv. It never launches a browser with the user's normal Firefox profile.
// Cancellation terminates and joins the helper before removing its files.
func Run(ctx context.Context, runtimePath string, config Config, stdout, stderr io.Writer) error {
	return runWithClient(ctx, runtimePath, config, stdout, stderr, clientScript)
}

// runWithClient is private to this package. Production callers always get
// the embedded clientScript; native tests may substitute a pinned historical
// client for same-run A/B measurements without affecting runtime configuration.
func runWithClient(ctx context.Context, runtimePath string, config Config, stdout, stderr io.Writer, scriptSource []byte) error {
	c, err := config.normalize()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(runtimePath) {
		return errors.New("Firefox runtime must be an absolute path to xpcshell")
	}
	info, err := os.Stat(runtimePath)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("Firefox xpcshell runtime is unavailable")
	}
	u, _ := cluster.Origin(c.Server)
	proxyPort := 443
	if u.Port() != "" {
		proxyPort, _ = strconv.Atoi(u.Port())
	}
	_, localPort, _ := net.SplitHostPort(c.Listen)
	listenPort, _ := strconv.Atoi(localPort)
	var ca []byte
	if c.CACert != "" {
		file, err := os.Open(c.CACert)
		if err != nil {
			return errors.New("cannot read Firefox CA certificate")
		}
		ca, err = io.ReadAll(io.LimitReader(file, (1<<20)+1))
		file.Close()
		if err != nil || len(ca) > 1<<20 {
			return errors.New("invalid Firefox CA certificate")
		}
	}
	private, err := os.MkdirTemp("", "foxtunnel-firefox-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(private)
	if err := os.Mkdir(filepath.Join(private, "profile"), 0700); err != nil {
		return err
	}
	runtimeNodes := make(map[string]tlsidentity.Policy, len(c.NodePolicies))
	for origin, policy := range c.NodePolicies {
		endpoint, _ := cluster.Origin(origin)
		key, _ := nativeOriginKey(endpoint)
		runtimeNodes[key] = policy
	}
	data, err := json.Marshal(runtimeConfig{NodePolicies: runtimeNodes, ServerName: c.ServerName, SPKIPin: c.SPKIPin, TLSClientProfile: c.TLSClientProfile, HTTP2ReceiveProfile: c.HTTP2ReceiveProfile, SOCKSToken: c.SOCKSToken, ProxyHost: u.Hostname(), ProxyPort: proxyPort, Authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)), Transport: c.Transport, ListenPort: listenPort, MaxConnections: c.MaxConnections, ConnectTimeoutMS: c.ConnectTimeoutMS, CAPEM: string(ca), IdleTimeoutMS: c.IdleTimeoutMS, DrainTimeoutMS: c.DrainTimeoutMS, MaxRetainedConnections: c.MaxRetainedConnections, StatsIntervalMS: c.StatsIntervalMS})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(private, "config.json"), data, 0600); err != nil {
		return err
	}
	script := filepath.Join(private, "client.js")
	if err := os.WriteFile(script, scriptSource, 0600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, runtimePath, "-g", filepath.Dir(runtimePath), "-a", filepath.Dir(runtimePath), "-f", script)
	cmd.Env = append(os.Environ(), "FOXTUNNEL_FIREFOX_ROOT="+private,
		"LD_LIBRARY_PATH="+filepath.Dir(runtimePath),
		// Gecko can initialize HTTP while loading its own chrome resources,
		// before client.js sets prefs. Match Mozilla's standalone xpcshell
		// harness: disable the unsupported socket process before XPCOM starts.
		"MOZ_DISABLE_SOCKET_PROCESS=1")
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("Firefox networking helper failed: %w", err)
	}
	return nil
}
