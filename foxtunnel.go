// Package foxtunnel embeds FoxTunnel independently of its CLI or any panel.
// This is an experimental API; pin a reviewed commit until a versioned release.
package foxtunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/SawaMEN/FoxTunnel/internal/access"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
	"github.com/SawaMEN/FoxTunnel/internal/enginestatus"
	"github.com/SawaMEN/FoxTunnel/internal/h2profile"
	"github.com/SawaMEN/FoxTunnel/internal/nodeperf"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"github.com/SawaMEN/FoxTunnel/internal/transportengine"
	"github.com/SawaMEN/FoxTunnel/internal/tunnel"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
)

const ProtocolDraft = buildinfo.ProtocolDraft
const HTTP2ReceiveFirefox158 = h2profile.Firefox158

// TLSClientFirefox158 opts into measured preferences on pinned NSS 3.130.
const TLSClientFirefox158 = nsstls.Firefox158

// ErrProtocolNegotiation identifies missing or incompatible wire confirmation.
var ErrProtocolNegotiation = tunnel.ErrProtocolNegotiation

var ErrCapacity = errors.New("foxtunnel client connection limit reached")

// TransportStatus contains only local aggregate transport counters and fixed codes.
type TransportStatus = enginestatus.Snapshot

// NodeStatus reports bounded passive HTTPS carrier observations per node.
// It contains origin hostnames, not credentials, paths or target addresses.
type NodeStatus = nodeperf.Snapshot

type Credentials struct{ Username, Password string }
type ClientConfig struct {
	// RequireProtocolNegotiation opts into strict draft/capability confirmation.
	// False preserves legacy interoperability. Configure both ends explicitly.
	RequireProtocolNegotiation bool

	ServerURL            string
	Credentials          Credentials
	CACertFile           string
	Engine               string // Empty/legacy preserves old selection; mozilla selects NSS and Neqo when available.
	TLSBackend           string // Empty selects auto (NSS for TCP if available, Go for default H3); Neqo uses NSS.
	Transport            string // Empty selects h2-connect.
	QUICBackend          string // Empty/quic-go preserves the default; neqo is an opt-in build.
	H3Fallback           string // Empty/none or h2; only before a Neqo HTTP request is created.
	QUICHandshakeTimeout time.Duration
	ServerName, SPKIPin  string
	XHTTPPath, XHTTPHost string
	HTTP2ReceiveProfile  string
	TLSClientProfile     string // Local opt-in NSS preferences; empty keeps the default.
	Padding              bool
	EnableUDP            bool // Experimental datagram API and SOCKS5 UDP; off by default.
	UDPStreaming         bool // Opt-in v2 persistent UDP stream; requires EnableUDP.
	ConnectTimeout       time.Duration
	MaxConnections       int // Combined TCP/UDP connections and pending operations; 0 uses 256.
	FallbackServers      []string
	Balance              string // Empty preserves failover; adaptive enables passive-metric route selection.
}

// Client is configured at construction and may be shared by concurrent callers.
// Close cancels pending TCP/UDP setup and closes its streams and SOCKS listeners.
type Client struct {
	core           *tunnel.Client
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	closed         bool
	pending, limit int
	conns          map[*ownedConn]struct{}
	udpConns       map[*UDPConn]struct{}
	listeners      map[net.Listener]struct{}
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.MaxConnections < 0 || config.ConnectTimeout < 0 {
		return nil, errors.New("negative client limit or timeout")
	}
	if config.UDPStreaming && !config.EnableUDP {
		return nil, errors.New("UDP streaming requires UDP to be enabled")
	}
	core, err := tunnel.NewClient(config.ServerURL, config.Credentials.Username, config.Credentials.Password, config.CACertFile)
	if err != nil {
		return nil, err
	}
	core.RequireProtocolNegotiation = config.RequireProtocolNegotiation

	success := false
	defer func() {
		if !success {
			core.Close()
		}
	}()
	plan, err := transportengine.Resolve(transportengine.Config{
		Engine: config.Engine, Transport: config.Transport,
		TLSBackend: config.TLSBackend, QUICBackend: config.QUICBackend,
		H3Fallback: config.H3Fallback, QUICHandshakeTimeout: config.QUICHandshakeTimeout,
		TLSClientProfile: config.TLSClientProfile, HTTP2ReceiveProfile: config.HTTP2ReceiveProfile,
	})
	if err != nil {
		return nil, err
	}
	if err = plan.Apply(core, config.ServerName, config.SPKIPin); err != nil {
		return nil, err
	}
	if err = core.SetXHTTPSettings(config.XHTTPPath, config.XHTTPHost); err != nil {
		return nil, err
	}
	if err = core.SetFallbackServers(config.FallbackServers); err != nil {
		return nil, err
	}
	mode := config.Balance
	if mode == "" {
		mode = "failover"
	}
	if err = core.SetBalance(mode); err != nil {
		return nil, err
	}
	limit := config.MaxConnections
	if limit == 0 {
		limit = 256
	}
	core.MaxConnections = limit
	core.ConnectTimeout = config.ConnectTimeout
	core.Padding = config.Padding
	core.EnableUDP = config.EnableUDP
	core.UDPStreaming = config.UDPStreaming
	ctx, cancel := context.WithCancel(context.Background())
	success = true
	return &Client{core: core, ctx: ctx, cancel: cancel, limit: limit, conns: make(map[*ownedConn]struct{}), udpConns: make(map[*UDPConn]struct{}), listeners: make(map[net.Listener]struct{})}, nil
}

// Status returns a concurrency-safe snapshot. No addresses or secrets.
func (c *Client) Status() TransportStatus {
	return c.core.TransportStatus()
}

// NodeStatuses returns an independent snapshot of measured node traffic.
// It neither probes nodes nor changes route selection.
func (c *Client) NodeStatuses() []NodeStatus {
	return c.core.NodeStatus()
}

// NotifyNetworkChange clears cached UDP unreachability after a confirmed
// Wi-Fi/cellular route change. Omit it when the platform provides no such
// signal: Mozilla mode retries HTTP/3 automatically after the cooldown.
func (c *Client) NotifyNetworkChange() error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	c.core.NotifyNetworkChange()
	return nil
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if c.pending+len(c.conns)+len(c.udpConns) >= c.limit {
		c.mu.Unlock()
		return nil, ErrCapacity
	}
	c.pending++
	c.mu.Unlock()
	setup, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	raw, err := c.core.DialContext(setup, network, address)
	stop()
	cancel()
	c.mu.Lock()
	c.pending--
	defer c.mu.Unlock()
	if c.closed {
		if raw != nil {
			raw.Close()
		}
		return nil, net.ErrClosed
	}
	if err != nil {
		return nil, err
	}
	return c.ownLocked(raw), nil
}
func (c *Client) ownLocked(raw net.Conn) *ownedConn {
	owned := &ownedConn{Conn: raw, owner: c}
	c.conns[owned] = struct{}{}
	return owned
}

// ServeSOCKS takes ownership of listener and closes it on return or Client.Close.
// SOCKS5 supports TCP and opt-in experimental UDP ASSOCIATE. No child process or panel is required.
func (c *Client) ServeSOCKS(listener net.Listener) error {
	return c.serveSOCKS(context.Background(), listener)
}

func (c *Client) serveSOCKS(ctx context.Context, listener net.Listener) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		listener.Close()
		return net.ErrClosed
	}
	c.listeners[listener] = struct{}{}
	c.mu.Unlock()
	defer func() { listener.Close(); c.mu.Lock(); delete(c.listeners, listener); c.mu.Unlock() }()
	service, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer func() { stop(); cancel() }()
	return c.core.ServeContext(service, &ownedListener{Listener: listener, owner: c})
}
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancel()
	conns := make([]*ownedConn, 0, len(c.conns))
	for conn := range c.conns {
		conns = append(conns, conn)
	}
	udpConns := make([]*UDPConn, 0, len(c.udpConns))
	for conn := range c.udpConns {
		udpConns = append(udpConns, conn)
	}
	listeners := make([]net.Listener, 0, len(c.listeners))
	for l := range c.listeners {
		listeners = append(listeners, l)
	}
	c.mu.Unlock()
	for _, l := range listeners {
		l.Close()
	}
	for _, conn := range conns {
		conn.Close()
	}
	for _, conn := range udpConns {
		conn.Close()
	}
	c.core.Close()
	return nil
}

type ownedConn struct {
	net.Conn
	owner *Client
	once  sync.Once
	err   error
}

func (c *ownedConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.owner.mu.Lock(); delete(c.owner.conns, c); c.owner.mu.Unlock() })
	return c.err
}

// SetLinger preserves TCP reset signalling through the supervised SOCKS adapter.
func (c *ownedConn) SetLinger(seconds int) error {
	if tcp, ok := c.Conn.(interface{ SetLinger(int) error }); ok {
		return tcp.SetLinger(seconds)
	}
	return errors.ErrUnsupported
}
func (c *ownedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

type ownedListener struct {
	net.Listener
	owner *Client
}

func (l *ownedListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.owner.mu.Lock()
		if l.owner.closed {
			l.owner.mu.Unlock()
			raw.Close()
			return nil, net.ErrClosed
		}
		if l.owner.pending+len(l.owner.conns)+len(l.owner.udpConns) >= l.owner.limit {
			l.owner.mu.Unlock()
			raw.Close()
			continue
		}
		conn := l.owner.ownLocked(raw)
		l.owner.mu.Unlock()
		return conn, nil
	}
}

// AccessUser configures an opaque stable account ID and a high-entropy Basic credential.
type AccessUser = access.User
type AccessPolicy = access.Document
type AccessSnapshot = access.Snapshot
type AccessController = access.Controller

// NewAccessController uses a Linux durable ledger when stateFile is nonempty.
// The caller owns Close. An empty stateFile explicitly selects volatile accounting.
func NewAccessController(policy AccessPolicy, stateFile string) (*AccessController, error) {
	return access.New(policy, stateFile)
}

type ServerConfig struct {
	// RequireProtocolNegotiation rejects authenticated legacy TCP/UDP requests.
	RequireProtocolNegotiation bool

	Access                   *AccessController // Alternative to Credentials; shared by all server transports.
	Credentials              Credentials
	XHTTPPath, XHTTPHost     string
	AllowPrivateDestinations bool // False rejects private/loopback/link-local targets.
	EnableUDP                bool // Experimental authenticated HTTPS datagram relay; off by default.
	MaxTunnels               int  // 0 uses 256.
	DialTimeout              time.Duration
	Padding                  bool
	Cover                    http.Handler // Public site for ordinary/rejected requests; nil returns 404.
}

// Server is an http.Handler for verified TLS 1.3 with HTTP/2 enabled by the host.
// The host owns certificates, HTTP listener lifecycle and deployment limits.
type Server struct{ core *tunnel.Server }

func NewServer(config ServerConfig) (*Server, error) {
	if (config.Access == nil && (config.Credentials.Username == "" || config.Credentials.Password == "" || strings.Contains(config.Credentials.Username, ":"))) || (config.Access != nil && (config.Credentials.Username != "" || config.Credentials.Password != "")) {
		return nil, errors.New("server credentials required")
	}
	if config.MaxTunnels < 0 || config.DialTimeout < 0 {
		return nil, errors.New("negative server limit or timeout")
	}
	settings, err := xhttp.Normalize(config.XHTTPPath, config.XHTTPHost)
	if err != nil {
		return nil, err
	}
	return &Server{core: &tunnel.Server{RequireProtocolNegotiation: config.RequireProtocolNegotiation, Access: config.Access, Username: config.Credentials.Username, Password: config.Credentials.Password, XHTTPSettings: settings, AllowPrivate: config.AllowPrivateDestinations, EnableUDP: config.EnableUDP, MaxTunnels: config.MaxTunnels, DialTimeout: config.DialTimeout, Padding: config.Padding, Cover: config.Cover}}, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 {
		http.NotFound(w, r)
		return
	}
	s.core.ServeHTTP(w, r)
}
