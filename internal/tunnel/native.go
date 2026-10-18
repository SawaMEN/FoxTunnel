package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
	"github.com/coder/websocket"
	"golang.org/x/net/http2"
)

const postPath = "/.well-known/foxtunnel-stream-v1"
const wsPath = "/.well-known/foxtunnel-ws-v1"
const targetHeader = "X-FoxTunnel-Target"

var errWSHandshake = i18n.Error("native WebSocket handshake rejected")

// SetTransport selects an explicit, native transport before serving or bond.
// Authentication, discovery and bonded RPCs use the same selected transport.
// No external proxy executable or automatic downgrade is involved.
func (c *Client) SetTransport(mode string) error {
	if mode == "" {
		mode = "h2-connect"
	}
	if mode != "h2-connect" && mode != "h2-post" && mode != "wss" && mode != "h3-post" && mode != "xhttp-stream-one" && mode != "xhttp-stream-up" && mode != "xhttp-packet-up" {
		return i18n.Error("unknown native transport (choose h2-connect, h2-post, h3-post, wss, xhttp-stream-one, xhttp-stream-up or xhttp-packet-up)")
	}
	if c.bondClient != nil || c.bondDiscovery != nil {
		return i18n.Error("configure transport before enabling bond")
	}
	old := c.nativeTransport
	c.nativeTransport = mode
	if err := c.SetTLSBackend(c.backend); err != nil {
		c.nativeTransport = old
		return err
	}
	return nil
}

func makeNativeTransport(mode, backend string, config *tls.Config, auth string, settings xhttp.Settings, receiveProfile, clientProfile string) (tlsTransport, error) {
	if err := nsstls.ValidateClientProfile(clientProfile); err != nil {
		return nil, err
	}
	if clientProfile == nsstls.Firefox158 && backend != "nss" {
		return nil, i18n.Error("TLS client profile requires NSS")
	}

	if mode == "xhttp-stream-one" || mode == "xhttp-stream-up" || mode == "xhttp-packet-up" {
		return newXHTTPTransport(mode, backend, config, auth, settings, receiveProfile, clientProfile)
	}
	if receiveProfile != "" && (mode == "wss" || mode == "h3-post") {
		return nil, i18n.Error("HTTP/2 receive profile requires an H2 or XHTTP transport")
	}
	if settings != (xhttp.Settings{}) {
		return nil, xhttp.ErrSettings
	}
	if mode == "h3-post" {
		if backend != "go" {
			return nil, i18n.Error("HTTP/3 requires Go QUIC TLS; NSS cannot be selected")
		}
		return newH3Transport(config), nil
	}
	if mode == "wss" {
		return newWSSTransport(backend, config, auth, clientProfile)
	}
	t, err := makeTLStransport(backend, config, receiveProfile, clientProfile)
	if err != nil {
		return nil, err
	}
	if mode == "h2-post" {
		return postTransport{tlsTransport: t, host: config.ServerName}, nil
	}
	return t, nil
}

type postTransport struct {
	tlsTransport
	host string
}

func (t postTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodConnect {
		r = r.Clone(r.Context())
		u := *r.URL
		u.Path = postPath
		r.URL = &u
		r.Method = http.MethodPost
		r.Header.Set(targetHeader, r.Host)
		r.Host = r.URL.Host
		if t.host != "" {
			r.Host = t.host
		}
		r.Header.Set("Content-Type", "application/octet-stream")
	}
	return t.tlsTransport.RoundTrip(r)
}

type wssTransport struct {
	*http2.Transport
	outer *http.Transport
}

func (t *wssTransport) CloseIdleConnections() {
	t.Transport.CloseIdleConnections()
	t.outer.CloseIdleConnections()
}

func newWSSTransport(backend string, config *tls.Config, auth, clientProfile string) (tlsTransport, error) {
	// Validate the build now, rather than silently switching away from NSS later.
	if backend == "nss" {
		probe, err := nsstls.NewTransportWithProfiles(config, "", clientProfile)
		if err != nil {
			return nil, err
		}
		probe.CloseIdleConnections()
	}
	cfg := config.Clone()
	cfg.NextProtos = []string{"http/1.1"}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	outer := &http.Transport{Protocols: protocols, TLSClientConfig: cfg, DisableCompression: true, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 90 * time.Second}
	if backend == "nss" {
		outer.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nsstls.DialTLSContextWithProfile(ctx, network, addr, cfg, clientProfile)
		}
	}
	client := &http.Client{Transport: outer, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	h2 := &http2.Transport{TLSClientConfig: config.Clone(), DisableCompression: true, IdleConnTimeout: 90 * time.Second}
	h2.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		u := url.URL{Scheme: "wss", Host: addr, Path: wsPath}
		header := make(http.Header)
		header.Set("Proxy-Authorization", auth)
		conn, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: client, HTTPHeader: header, Host: cfg.ServerName, CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			if resp != nil {
				return nil, errors.Join(errWSHandshake, err)
			}
			return nil, err
		}
		// The HTTP/2 transport owns the socket after setup; the dial context must
		// not become the lifetime of a shared, multiplexed connection.
		return wsSocket(conn), nil
	}
	return &wssTransport{Transport: h2, outer: outer}, nil
}

// WebSocket messages are bounded independently of HTTP/2 DATA framing.
type wsConn struct {
	net.Conn
	ws *websocket.Conn
}

func (c wsConn) Close() error {
	// Abort network I/O first, then let NetConn stop deadline timers and release
	// its read/write contexts without waiting for a peer close handshake.
	err := c.ws.CloseNow()
	_ = c.Conn.Close()
	return err
}

func (c wsConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := c.Conn.Write(p[:min(len(p), 32<<10)])
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, net.ErrClosed
		}
	}
	return total, nil
}
func wsSocket(c *websocket.Conn) net.Conn {
	n := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	c.SetReadLimit(64 << 10)
	return wsConn{Conn: n, ws: c}
}

func (s *Server) serveWSS(w http.ResponseWriter, r *http.Request) {
	limit := s.MaxTunnels
	if limit <= 0 {
		limit = 256
	}
	if s.activeWebSockets.Add(1) > int64(limit) {
		s.activeWebSockets.Add(-1)
		http.Error(w, "server busy", 503)
		return
	}
	defer s.activeWebSockets.Add(-1)
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	inner := &http2.Server{MaxConcurrentStreams: 32, MaxUploadBufferPerConnection: 1 << 20, MaxUploadBufferPerStream: 64 << 10, IdleTimeout: 90 * time.Second}
	inner.ServeConn(wsSocket(conn), &http2.ServeConnOpts{Context: context.Background(), BaseConfig: &http.Server{MaxHeaderBytes: 32 << 10}, Handler: s})
}

func basicAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// Mozilla NSS supplies the outer TLS handshake; Go supplies the HTTP/2 framing.
// The inner connection is plaintext HTTP/2 inside the verified HTTPS carrier.
func newXHTTPTransport(mode, backend string, config *tls.Config, auth string, settings xhttp.Settings, receiveProfile, clientProfile string) (tlsTransport, error) {
	outer, err := makeTLStransport(backend, config, receiveProfile, clientProfile)
	if err != nil {
		return nil, err
	}
	inner := &http2.Transport{TLSClientConfig: config.Clone(), DisableCompression: true, IdleConnTimeout: 90 * time.Second}
	t := &xhttpTransport{Transport: inner, outer: outer, carriers: make(map[net.Conn]bool)}
	inner.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		conn, err := xhttp.DialWithSettings(ctx, outer, "https://"+addr, mode, auth, config.ServerName, settings)
		if err != nil {
			return nil, err
		}
		t.mu.Lock()
		if t.draining && t.active == 0 {
			t.mu.Unlock()
			conn.Close()
			return nil, net.ErrClosed
		}
		t.carriers[conn] = true
		t.mu.Unlock()
		return &trackedCarrier{Conn: conn, owner: t}, nil
	}
	return t, nil
}

type xhttpTransport struct {
	*http2.Transport
	outer    tlsTransport
	mu       sync.Mutex
	active   int
	draining bool
	carriers map[net.Conn]bool
}
type trackedCarrier struct {
	net.Conn
	owner *xhttpTransport
}

func (c *trackedCarrier) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.owner.carriers, c.Conn)
	c.owner.mu.Unlock()
	return err
}
func (t *xhttpTransport) closeDrainedLocked() {
	if !t.draining || t.active != 0 {
		return
	}
	for conn := range t.carriers {
		_ = conn.Close()
		delete(t.carriers, conn)
	}
	t.draining = false
}
func (t *xhttpTransport) CloseIdleConnections() {
	// A carrier stays an active outer request while its inner HTTP/2 is idle.
	// Retire it after its last inner body is released, preserving active streams.
	t.mu.Lock()
	t.draining = true
	t.closeDrainedLocked()
	t.mu.Unlock()
	t.Transport.CloseIdleConnections()
	t.outer.CloseIdleConnections()
}
func (t *xhttpTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.active++
	t.mu.Unlock()
	release := func() { t.mu.Lock(); t.active--; t.closeDrainedLocked(); t.mu.Unlock() }
	resp, err := t.Transport.RoundTrip(r)
	if err != nil {
		release()
		return nil, err
	}
	resp.Body = &carrierBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}

type carrierBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *carrierBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}
func (b *carrierBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.release); return err }
func (s *Server) serveXHTTP(w http.ResponseWriter, r *http.Request) {
	s.xhttpOnce.Do(func() {
		s.xhttpServer = &xhttp.Server{Settings: s.XHTTPSettings, MaxSessions: s.MaxTunnels, Authorized: s.authorized, ServeConn: func(conn net.Conn, outer *http.Request) {
			defer conn.Close()
			inner := &http2.Server{MaxConcurrentStreams: 32, MaxUploadBufferPerConnection: 1 << 20, MaxUploadBufferPerStream: 64 << 10, IdleTimeout: 90 * time.Second}
			inner.ServeConn(conn, &http2.ServeConnOpts{Context: context.Background(), BaseConfig: &http.Server{MaxHeaderBytes: 32 << 10}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.TLS = outer.TLS; s.ServeHTTP(w, r) })})
		}}
	})
	s.xhttpServer.ServeHTTP(w, r)
}

// SetXHTTPSettings applies a common carrier route to every cluster origin.
// Select an XHTTP transport first; call before serving or enabling bond.
func (c *Client) SetXHTTPSettings(path, host string) error {
	if c.bondClient != nil || c.bondDiscovery != nil {
		return i18n.Error("configure transport before enabling bond")
	}
	settings, err := xhttp.Normalize(path, host)
	if err != nil {
		return i18n.Error("invalid XHTTP path or Host")
	}
	if path == "" && host == "" {
		settings = xhttp.Settings{}
	}
	if !xhttp.IsMode(c.nativeTransport) && settings != (xhttp.Settings{}) {
		return i18n.Error("XHTTP settings require an XHTTP transport")
	}
	old := c.xhttpSettings
	c.xhttpSettings = settings
	if err := c.SetTLSBackend(c.backend); err != nil {
		c.xhttpSettings = old
		return err
	}
	return nil
}
