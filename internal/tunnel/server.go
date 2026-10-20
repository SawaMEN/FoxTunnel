package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/authheader"
	"github.com/SawaMEN/FoxTunnel/internal/bond"
	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"github.com/SawaMEN/FoxTunnel/internal/xhttp"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server terminates authenticated native H2 CONNECT, H2/H3 POST and WSS.
// It has no Firefox fingerprint parity. Padding is an opt-in experiment.
type Server struct {
	// RequireProtocolNegotiation rejects authenticated legacy TCP/UDP requests.
	// Outer WSS/XHTTP handshakes and cluster/bond extensions are separate.
	RequireProtocolNegotiation bool

	// Access is mutually exclusive with legacy credentials; set before serving.
	Access *access.Controller

	XHTTPSettings xhttp.Settings // Configure before serving; common cluster route.
	Username      string
	Password      string
	AllowPrivate  bool
	// EnableUDP admits bounded authenticated one-shot datagram relay requests.
	EnableUDP   bool
	Resolver    *net.Resolver
	DialTimeout time.Duration
	// Padding enables support for explicitly negotiated initial-v1 records.
	Padding bool
	// MaxTunnels bounds authenticated dialing/relay work across this Server.
	// Zero uses 256. Configure before serving and do not copy Server after use.
	MaxTunnels int
	// MaxCoverRequests limits concurrent public/unauthorized HTTP handlers,
	// independently of authenticated tunnels. Zero uses 64. Configure before
	// serving and do not copy Server after first use.
	MaxCoverRequests    int
	activeTunnels       atomic.Int64
	activeCoverRequests atomic.Int64
	activeWebSockets    atomic.Int64
	xhttpOnce           sync.Once
	xhttpServer         *xhttp.Server
	// Cover serves ordinary requests and rejected probes. Nil returns a plain 404.
	Cover http.Handler
	// Bond is an opt-in hub or relay, behind the same authentication boundary.
	Bond http.Handler
	// BondRelayOnly prevents managed relays from becoming unmetered direct exits.
	BondRelayOnly bool
	// Cluster is authenticated coordinator discovery on the common exit.
	Cluster http.Handler
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if protocolRequest(r) && s.authorized(r) && !s.acceptProtocol(w, r) {
		return
	}
	settings, settingsErr := xhttp.Normalize(s.XHTTPSettings.Path, s.XHTTPSettings.Host)
	if settingsErr == nil && xhttp.MatchesAt(r, settings) && r.ProtoMajor == 2 && s.authorized(r) {
		s.serveXHTTP(w, r)
		return
	}
	if r.Method == http.MethodGet && r.ProtoMajor == 1 && r.TLS != nil && r.URL.Path == wsPath && s.authorized(r) {
		s.serveWSS(w, r)
		return
	}
	if r.Method == http.MethodPost && (r.ProtoMajor == 2 || r.ProtoMajor == 3) && r.URL.Path == postPath && s.authorized(r) {
		r = r.Clone(r.Context())
		r.Method = http.MethodConnect
		r.Host = r.Header.Get(targetHeader)
		r.Header.Del(targetHeader)
	}

	if s.Cluster != nil && r.Method == http.MethodGet && (r.ProtoMajor == 2 || r.ProtoMajor == 3) && r.URL.Path == cluster.Path && s.authorized(r) {
		if !s.acquireTunnel() {
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}
		defer s.activeTunnels.Add(-1)
		s.Cluster.ServeHTTP(w, r)
		return
	}
	if s.Bond != nil && r.Method == http.MethodPost && (r.ProtoMajor == 2 || r.ProtoMajor == 3) && r.URL.Path == bond.Path && s.authorized(r) {
		if !s.acquireTunnel() {
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}
		defer s.activeTunnels.Add(-1)
		s.Bond.ServeHTTP(w, r)
		return
	}
	if s.BondRelayOnly {
		s.cover(w, r)
		return
	}
	if s.EnableUDP && r.Method == http.MethodPost && r.URL.Path == udpPath &&
		(r.ProtoMajor == 2 || r.ProtoMajor == 3) && s.authorized(r) {
		s.serveUDP(w, r)
		return
	}
	if s.EnableUDP && r.Method == http.MethodPost && r.URL.Path == udpStreamPath &&
		(r.ProtoMajor == 2 || r.ProtoMajor == 3) && s.authorized(r) {
		s.serveUDPStream(w, r)
		return
	}
	// Select the tunnel only after authentication; rejected requests use the
	// same handler as the public website and never dial a destination.
	if r.Method != http.MethodConnect || (r.ProtoMajor != 2 && r.ProtoMajor != 3) || !s.authorized(r) {
		s.cover(w, r)
		return
	}
	padded, err := paddingRequested(r.Header)
	if err != nil || (padded && !s.Padding) {
		http.Error(w, "unsupported padding mode", http.StatusBadRequest)
		return
	}
	host, port, err := splitTarget(r.Host)
	if err != nil {
		http.Error(w, "invalid CONNECT authority", http.StatusBadRequest)
		return
	}
	if !s.acquireTunnel() {
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}
	defer s.activeTunnels.Add(-1)
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout())
	upstream, err := s.dialTarget(ctx, host, port)
	cancel()
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, access.ErrLimited) || errors.Is(err, access.ErrQuota) {
			status = http.StatusTooManyRequests
		}
		http.Error(w, "destination unavailable", status)
		return
	}
	defer upstream.Close()
	// A disconnected H2 stream must release a silent destination socket too.
	stopClose := context.AfterFunc(r.Context(), func() { _ = upstream.Close() })
	defer stopClose()

	// HTTP/2 and HTTP/3 allow reading the request while streaming a response.
	if padded {
		w.Header().Set(paddingHeader, paddingVersion)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}
	f.Flush()

	var incoming io.Reader = r.Body
	var outgoing io.Writer = flushingWriter{w: w, flusher: f}
	if padded {
		incoming = newPaddingReader(r.Body)
		outgoing = newPaddingWriter(outgoing)
	}
	incomingDone := make(chan struct{})
	go func() {
		defer close(incomingDone)
		_, err := fastCopy(upstream, incoming)
		if err != nil {
			_ = upstream.Close()
			return
		}
		if tcp, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		}
	}()

	// Flush small chunks immediately; otherwise an interactive tunnel can stall.
	_, downloadErr := fastCopyHTTPResponse(outgoing, upstream)
	_ = upstream.Close()
	_ = r.Body.Close()
	<-incomingDone
	if downloadErr != nil {
		// Headers may already be committed. Returning normally would emit a
		// successful END_STREAM and disguise a truncated TCP response as EOF.
		// net/http converts ErrAbortHandler to a stream reset without a log
		// stack, after the destination and upload worker have been released.
		panic(http.ErrAbortHandler)
	}
}

func (s *Server) authorized(r *http.Request) bool {
	if s.Access != nil {
		return access.Authenticated(r.Context())
	}

	user, pass, ok := authheader.Parse(r.Header)
	if !ok || s.Username == "" || s.Password == "" {
		return false
	}
	// Fixed-size digests avoid prefix/length information from direct comparison.
	u1, u2 := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(s.Username))
	p1, p2 := sha256.Sum256([]byte(pass)), sha256.Sum256([]byte(s.Password))
	return subtle.ConstantTimeCompare(u1[:], u2[:])&subtle.ConstantTimeCompare(p1[:], p2[:]) == 1
}

func (s *Server) timeout() time.Duration {
	if s.DialTimeout > 0 {
		return s.DialTimeout
	}
	return 10 * time.Second
}

func splitTarget(address string) (string, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return "", "", errors.New(i18n.Text("missing host or port"))
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", errors.New(i18n.Text("invalid port"))
	}
	return host, port, nil
}

func (s *Server) dialTarget(ctx context.Context, host, port string) (net.Conn, error) {
	return access.Dial(ctx, func(ctx context.Context) (net.Conn, error) { return s.dialRawTarget(ctx, host, port) })
}
func (s *Server) dialRawTarget(ctx context.Context, host, port string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: s.timeout(), KeepAlive: 30 * time.Second}
	return s.dialResolvedTarget(ctx, host, port, dialer.DialContext)
}

// dialResolvedTarget owns resolution and passes only filtered numeric addresses
// to the socket dialer. Keep DNS and dialing in this single policy boundary.
func (s *Server) dialResolvedTarget(ctx context.Context, host, port string, dial contextDial) (net.Conn, error) {
	resolver := s.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		ips = []netip.Addr{ip.Unmap()}
	} else {
		var err error
		ips, err = resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	// Filter and pin all addresses before racing IPv4/IPv6; never re-resolve a
	// hostname in the dialer (which would permit DNS rebinding past the filter).
	permitted := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if s.AllowPrivate || safePublicIP(ip) {
			permitted = append(permitted, ip)
		}
	}
	if len(permitted) == 0 {
		return nil, errors.New(i18n.Text("no permitted destination addresses"))
	}
	return dialFamilies(ctx, permitted, port, 250*time.Millisecond, dial)
}

type flushingWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (fw flushingWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	fw.flusher.Flush()
	return n, err
}

// acquireCover bounds potentially slow local file reads and custom cover
// handlers without consuming the admission slots reserved for tunnels.
func (s *Server) acquireCover() bool {
	limit := s.MaxCoverRequests
	if limit <= 0 {
		limit = 64
	}
	for {
		active := s.activeCoverRequests.Load()
		if active >= int64(limit) {
			return false
		}
		if s.activeCoverRequests.CompareAndSwap(active, active+1) {
			return true
		}
	}
}

func (s *Server) acquireTunnel() bool {
	limit := s.MaxTunnels
	if limit <= 0 {
		limit = 256
	}
	for {
		active := s.activeTunnels.Load()
		if active >= int64(limit) {
			return false
		}
		if s.activeTunnels.CompareAndSwap(active, active+1) {
			return true
		}
	}
}
