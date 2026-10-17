package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Server is an authenticated HTTP/2 CONNECT forward proxy. It has no
// Firefox fingerprinting or custom wire protocol; it is a baseline.
type Server struct {
	Username     string
	Password     string
	AllowPrivate bool
	Resolver     *net.Resolver
	DialTimeout  time.Duration
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "<!doctype html><html><head><title>FoxTunnel</title></head><body><h1>Welcome</h1></body></html>\n")
		return
	}
	// HTTP/1.1 hijacking is deliberately not implemented. Require multiplexed h2.
	if r.ProtoMajor != 2 || !s.authorized(r) {
		http.NotFound(w, r)
		return
	}
	host, port, err := splitTarget(r.Host)
	if err != nil {
		http.Error(w, "invalid CONNECT authority", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.timeout())
	upstream, err := s.dialTarget(ctx, host, port)
	cancel()
	if err != nil {
		http.Error(w, "destination unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	// The server can read r.Body while streaming the response only under HTTP/2.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}
	f.Flush()

	incomingDone := make(chan struct{})
	go func() {
		defer close(incomingDone)
		_, _ = io.Copy(upstream, r.Body)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()

	// Flush small chunks immediately; otherwise an interactive tunnel can stall.
	_, _ = io.Copy(flushingWriter{w: w, flusher: f}, upstream)
	_ = upstream.Close()
	_ = r.Body.Close()
	<-incomingDone
}

func (s *Server) authorized(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:6], "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[6:]))
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(decoded), ":")
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
		return "", "", errors.New("missing host or port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("invalid port")
	}
	return host, port, nil
}

func (s *Server) dialTarget(ctx context.Context, host, port string) (net.Conn, error) {
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
	var lastErr error
	for _, ip := range ips {
		ip = ip.Unmap()
		if !s.AllowPrivate && !safePublicIP(ip) {
			continue
		}
		dialer := net.Dialer{Timeout: s.timeout(), KeepAlive: 30 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no permitted destination addresses")
}

func safePublicIP(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Shared address space, documentation and benchmark ranges are not WAN destinations.
	for _, prefix := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "fc00::/7"} {
		p := netip.MustParsePrefix(prefix)
		if p.Contains(ip) {
			return false
		}
	}
	return true
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
