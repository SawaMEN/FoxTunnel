package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/bond"
	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
	"github.com/SawaMEN/FoxTunnel/internal/enginestatus"
	"github.com/SawaMEN/FoxTunnel/internal/h2profile"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

// Client exposes local SOCKS5 TCP over the selected native HTTPS transport.
// NSS is the default in NSS-tagged Linux builds for TCP transports; HTTP/3 defaults to Go QUIC; explicit Neqo uses NSS.
type Client struct {
	ServerURL  *url.URL
	Username   string
	Password   string
	CACertFile string
	// MaxConnections bounds local SOCKS sockets, including incomplete handshakes.
	// Configure before Serve; zero uses 256.
	MaxConnections int
	// ConnectTimeout bounds setup only, never the lifetime of an open stream.
	// Set before calling Serve; zero uses 15 seconds.
	ConnectTimeout time.Duration
	// Padding is an opt-in experiment; configure before Serve.
	Padding bool
	// FallbackAttemptTimeout applies only with multiple configured endpoints.
	// Zero uses five seconds; ConnectTimeout bounds all attempts together.
	FallbackAttemptTimeout time.Duration
	fallbackServers        []*url.URL
	preferredEndpoint      atomic.Uint32
	schedulerMu            sync.Mutex
	balance                string
	nextEndpoint           uint64
	activeEndpoints        [maxProxyEndpoints]int
	endpointFailures       [maxProxyEndpoints]uint8
	endpointRetryAt        [maxProxyEndpoints]time.Time
	transport              interface {
		http.RoundTripper
		CloseIdleConnections()
	}
	// BondPipeline is 0 (automatic), 4 or 8; set before EnableBond.
	BondPipeline int
	// BondLanes is an experimental local opt-in; set before enabling bond.
	BondLanes        bool
	bondClient       *bond.Client
	bondDiscovery    *bondDiscovery
	tlsConfig        *tls.Config
	identity         tlsidentity.Policy
	backend          string
	nativeTransport  string
	quic             quicSettings
	status           *enginestatus.Recorder
	h2ReceiveProfile string
	tlsClientProfile string
	xhttpSettings    xhttp.Settings
}

func NewClient(rawURL, user, password, caFile string) (*Client, error) {
	u, err := parseServerURL(rawURL)
	if err != nil {
		return nil, err
	}
	if user == "" || password == "" || strings.Contains(user, ":") {
		return nil, errors.New(i18n.Text("nonempty credentials and a username without colon are required"))
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf(i18n.Text("system CA store: %w"), err)
	}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, errors.New(i18n.Text("CA file contains no PEM certificates"))
		}
	}
	c := &Client{ServerURL: u, Username: user, Password: password, CACertFile: caFile, status: enginestatus.New()}
	c.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ClientSessionCache: tls.NewLRUClientSessionCache(32)}
	c.transport = &identityPool{base: newGoTransport(c.tlsConfig), config: c.tlsConfig.Clone(), backend: "go", primary: u.Scheme + "://" + u.Host, entries: make(map[string]identityEntry)}
	c.backend = "auto"
	// Initialize the selected backend eagerly: never conceal an unusable NSS build.
	if buildinfo.NSSAvailable {
		if err := c.SetTLSBackend("auto"); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func newGoTransport(config *tls.Config) *http.Transport {
	t, _ := newGoTransportWithProfile(config, "")
	return t
}
func newGoTransportWithProfile(config *tls.Config, profile string) (*http.Transport, error) {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	t := &http.Transport{
		Protocols: protocols,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialGoH2(ctx, network, addr, config)
		},
		TLSClientConfig:   config.Clone(),
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2: true, DisableCompression: true,
		MaxIdleConns: 64, MaxIdleConnsPerHost: 16,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
	}
	if err := h2profile.Configure(t, profile); err != nil {
		return nil, err
	}
	return t, nil
}

// TransportStatus returns aggregate, privacy-safe engine observations.
func (c *Client) TransportStatus() enginestatus.Snapshot {
	return c.status.Snapshot()
}

// SetEngineStatus is called after transport configuration succeeds.
func (c *Client) SetEngineStatus(engine, transport, tlsBackend, quicBackend, fallback string) {
	c.status.Configure(engine, transport, tlsBackend, quicBackend, fallback)
}

// SetTLSBackend selects a backend before Serve starts. "auto" uses NSS on
// supported TCP transports when compiled in, but Go QUIC for HTTP/3 unless Neqo is explicitly configured.
// Explicit "nss" never silently falls back to Go.
func (c *Client) SetTLSBackend(name string) error {
	if c.bondClient != nil || c.bondDiscovery != nil {
		return i18n.Error("configure TLS before enabling bond")
	}
	switch name {
	case "auto", "go", "nss":
	default:
		return fmt.Errorf(i18n.Text("unknown TLS backend %q (choose auto, go or nss)"), name)
	}
	resolved := name
	if name == "auto" {
		resolved = "go"
		if (buildinfo.NSSAvailable && c.nativeTransport != "h3-post") || c.quic.backend == "neqo" {
			resolved = "nss"
		}
	}
	transport, err := makeNativeTransport(c.nativeTransport, resolved, c.tlsConfig, basicAuth(c.Username, c.Password), c.xhttpSettings, c.h2ReceiveProfile, c.tlsClientProfile, c.quic)
	if err != nil {
		return err
	}
	c.transport.CloseIdleConnections()
	c.transport = &identityPool{base: transport, config: c.tlsConfig.Clone(), backend: resolved, mode: c.nativeTransport, quic: c.quic, h2ReceiveProfile: c.h2ReceiveProfile, tlsClientProfile: c.tlsClientProfile, xhttpSettings: c.xhttpSettings, auth: basicAuth(c.Username, c.Password), primary: c.ServerURL.Scheme + "://" + c.ServerURL.Host, policy: c.identity, entries: make(map[string]identityEntry)}
	c.backend = name
	return nil
}

func (c *Client) Close() { c.transport.CloseIdleConnections() }

// NotifyNetworkChange is an optional integration hook for OS connectivity
// changes (e.g. switching Wi-Fi/mobile networks). It clears stale negative
// Neqo reachability observations and retires idle sockets without terminating
// active streams or weakening TLS identity verification. Otherwise, H3 will
// be probed automatically when the 30-second cooldown expires.
func (c *Client) NotifyNetworkChange() {
	c.status.NetworkChanged()
	if pool, ok := c.transport.(*identityPool); ok {
		pool.NetworkChanged()
	} else {
		c.transport.CloseIdleConnections()
	}
}

func (c *Client) Serve(listener net.Listener) error {
	return c.ServeContext(context.Background(), listener)
}

// ServeContext cancels SOCKS relay requests and closes the listener on ctx end.
func (c *Client) ServeContext(ctx context.Context, listener net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	limit := c.MaxConnections
	if limit <= 0 {
		limit = 256
	}
	slots := make(chan struct{}, limit)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			go func() { defer func() { <-slots }(); c.handleContext(ctx, conn) }()
		default:
			_ = conn.Close()
		}
	}
}

func (c *Client) handle(conn net.Conn) { c.handleContext(context.Background(), conn) }
func (c *Client) handleContext(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	target, err := socks5Handshake(conn)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	if c.bondClient != nil || c.bondDiscovery != nil {
		c.handleBond(conn, target)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := c.openTunnel(ctx, target)
	if err != nil {
		_ = socks5Reply(conn, 0x05)
		return
	}
	defer stream.close()
	writer := stream.writer
	resp := stream.response
	var upload io.Writer = writer
	var download io.Reader = resp.Body
	if c.Padding {
		upload = newPaddingWriter(writer)
		download = newPaddingReader(resp.Body)
	}
	if err := socks5Reply(conn, 0x00); err != nil {
		return
	}

	_ = conn.SetWriteDeadline(time.Time{})

	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		_, err := io.Copy(upload, conn)
		_ = writer.CloseWithError(err)
		if err != nil {
			cancel()
		}
	}()
	_, _ = io.Copy(conn, download)
	cancel()
	_ = conn.Close()
	_ = writer.Close()
	<-uploadDone
}

func socks5Handshake(conn net.Conn) (string, error) {
	var hello [2]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil {
		return "", err
	}
	if hello[0] != 5 || hello[1] == 0 {
		return "", errors.New(i18n.Text("unsupported SOCKS greeting"))
	}
	methods := make([]byte, int(hello[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	noAuth := false
	for _, m := range methods {
		if m == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = conn.Write([]byte{5, 0xff})
		return "", errors.New(i18n.Text("SOCKS no-auth method unavailable"))
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var h [4]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return "", err
	}
	if h[0] != 5 || h[1] != 1 || h[2] != 0 {
		_ = socks5Reply(conn, 0x07)
		return "", errors.New(i18n.Text("only SOCKS CONNECT is supported"))
	}
	var host string
	switch h[3] {
	case 1:
		var addr [4]byte
		if _, err := io.ReadFull(conn, addr[:]); err != nil {
			return "", err
		}
		host = net.IP(addr[:]).String()
	case 4:
		var addr [16]byte
		if _, err := io.ReadFull(conn, addr[:]); err != nil {
			return "", err
		}
		host = net.IP(addr[:]).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return "", err
		}
		if n[0] == 0 {
			return "", errors.New(i18n.Text("empty hostname"))
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		_ = socks5Reply(conn, 0x08)
		return "", errors.New(i18n.Text("unsupported SOCKS address type"))
	}
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(p[:])
	if port == 0 || strings.ContainsAny(host, "\x00\r\n") {
		return "", errors.New(i18n.Text("invalid destination"))
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func socks5Reply(w io.Writer, code byte) error {
	if conn, ok := w.(net.Conn); ok {
		_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	}
	_, err := w.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// SetHTTP2ReceiveProfile changes only the outer H2 receive configuration.
// Configure before Serve and before enabling bond/discovery.
func (c *Client) SetHTTP2ReceiveProfile(name string) error {
	if err := h2profile.Validate(name); err != nil {
		return err
	}
	if name == "default" {
		name = ""
	}
	if c.bondClient != nil || c.bondDiscovery != nil {
		return i18n.Error("configure transport before enabling bond")
	}
	old := c.h2ReceiveProfile
	c.h2ReceiveProfile = name
	if err := c.SetTLSBackend(c.backend); err != nil {
		c.h2ReceiveProfile = old
		return err
	}
	return nil
}

// SetTLSClientProfile applies socket-local NSS preferences before serving.
func (c *Client) SetTLSClientProfile(name string) error {
	if err := nsstls.ValidateClientProfile(name); err != nil {
		return err
	}
	if name == "default" {
		name = ""
	}
	if c.bondClient != nil || c.bondDiscovery != nil {
		return i18n.Error("configure TLS before enabling bond")
	}
	old := c.tlsClientProfile
	c.tlsClientProfile = name
	if err := c.SetTLSBackend(c.backend); err != nil {
		c.tlsClientProfile = old
		return err
	}
	return nil
}
