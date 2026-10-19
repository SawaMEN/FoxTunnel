//go:build neqo && cgo && linux && amd64

package neqo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
)

const (
	maxOrigins  = 8
	maxStreams  = 32
	chunkSize   = 32 << 10
	maxMetadata = 1 << 20
	maxHeaders  = 64 << 10
)

type transport struct {
	config  *tls.Config
	timeout time.Duration
	mu      sync.Mutex
	origins map[string]*connection
}
type connection struct {
	tlsState           tls.ConnectionState
	owner              *transport
	origin, addr, name string
	ctx                context.Context
	cancel             context.CancelFunc
	ready, done        chan struct{}
	readyErr           error
	commands           chan command
	active             int
	touched            time.Time
}
type command struct {
	kind   byte
	stream *stream
	data   []byte
	reply  chan result
}
type result struct {
	n   int
	fin bool
	err error
}
type headerResult struct {
	response *http.Response
	err      error
}
type stream struct {
	conn                     *connection
	req                      *http.Request
	id                       uint64
	headers                  chan headerResult
	uploadDone               chan struct{}
	closed                   chan struct{}
	once                     sync.Once
	readMu                   sync.Mutex
	errorMu                  sync.Mutex
	terminalError            error
	stopMu                   sync.Mutex
	stop                     func() bool
	pendingRead, pendingSend *command
	recvFin                  bool
	headerSeen               bool
}

func NewTransport(config Config) (Transport, error) {
	if config.TLS == nil || config.TLS.InsecureSkipVerify || config.TLS.VerifyPeerCertificate != nil || len(config.TLS.Certificates) > 0 || config.TLS.GetClientCertificate != nil {
		return nil, errors.New("unsupported or insecure Neqo TLS settings")
	}
	if (config.TLS.MinVersion > tls.VersionTLS13) || (config.TLS.MaxVersion != 0 && config.TLS.MaxVersion < tls.VersionTLS13) {
		return nil, errors.New("Neqo requires TLS 1.3")
	}
	timeout := config.HandshakeTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, errors.New("Neqo handshake timeout must be 100ms through 10s")
	}
	// Initialize/validate ABI and linked runtime before an explicit backend is accepted.
	checked := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		_, err := newEngineCheck()
		checked <- err
	}()
	if err := <-checked; err != nil {
		return nil, err
	}
	return &transport{config: config.TLS.Clone(), timeout: timeout, origins: make(map[string]*connection)}, nil
}
func newEngineCheck() (bool, error) {
	if err := checkABI(); err != nil {
		return false, err
	}
	return true, nil
}
func (t *transport) acquire(u *url.URL) (*connection, error) {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" {
		return nil, errors.New("Neqo requires an HTTPS origin")
	}
	key := u.Scheme + "://" + u.Host
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.origins[key]
	if c != nil {
		select {
		case <-c.done:
			delete(t.origins, key)
			c = nil
		default:
		}
	}
	if c == nil {
		if len(t.origins) >= maxOrigins {
			var old *connection
			var oldKey string
			for k, p := range t.origins {
				if p.active == 0 && (old == nil || p.touched.Before(old.touched)) {
					old = p
					oldKey = k
				}
			}
			if old == nil {
				return nil, ErrCapacity
			}
			old.cancel()
			delete(t.origins, oldKey)
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		name := t.config.ServerName
		if name == "" {
			name = u.Hostname()
		}
		ctx, cancel := context.WithCancel(context.Background())
		c = &connection{owner: t, origin: key, addr: net.JoinHostPort(u.Hostname(), port), name: name, ctx: ctx, cancel: cancel, ready: make(chan struct{}), done: make(chan struct{}), commands: make(chan command, 2*maxStreams)}
		t.origins[key] = c
		go c.run()
	}
	if c.active >= maxStreams {
		return nil, ErrCapacity
	}
	c.active++
	c.touched = time.Now()
	return c, nil
}
func (c *connection) release() {
	c.owner.mu.Lock()
	c.active--
	c.touched = time.Now()
	c.owner.mu.Unlock()
}
func (c *connection) wait(ctx context.Context) error {
	select {
	case <-c.ready:
		return c.readyErr
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		<-c.ready
		if c.readyErr != nil {
			return c.readyErr
		}
		return errClosed
	}
}
func (t *transport) Probe(ctx context.Context, u *url.URL) error {
	c, err := t.acquire(u)
	if err != nil {
		return err
	}
	defer c.release()
	err = c.wait(ctx)
	if err != nil && ctx.Err() != nil {
		t.mu.Lock()
		if c.active == 1 {
			c.cancel()
		}
		t.mu.Unlock()
	}
	return err
}
func (t *transport) CloseIdleConnections() {
	t.mu.Lock()
	var closing []*connection
	for k, c := range t.origins {
		if c.active == 0 {
			delete(t.origins, k)
			c.cancel()
			closing = append(closing, c)
		}
	}
	t.mu.Unlock()
	for _, c := range closing {
		<-c.done
	}
}
func (t *transport) RoundTrip(r *http.Request) (*http.Response, error) {
	bodyOwned := false
	defer func() {
		if !bodyOwned && r != nil && r.Body != nil {
			r.Body.Close()
		}
	}()
	metadata, err := requestMetadata(r)
	if err != nil {
		return nil, err
	}
	c, err := t.acquire(r.URL)
	if err != nil {
		return nil, err
	}
	if err = c.wait(r.Context()); err != nil {
		if r.Context().Err() != nil {
			t.mu.Lock()
			if c.active == 1 {
				c.cancel()
			}
			t.mu.Unlock()
		}
		c.release()
		return nil, err
	}
	s := &stream{conn: c, req: r, headers: make(chan headerResult, 1), uploadDone: make(chan struct{}), closed: make(chan struct{})}
	out, err := c.call(r.Context(), command{kind: 'o', stream: s, data: metadata})
	if err != nil || out.err != nil {
		c.release()
		return nil, errors.Join(err, out.err)
	}
	bodyOwned = true
	go s.upload()
	s.stopMu.Lock()
	select {
	case <-s.closed:
	default:
		s.stop = context.AfterFunc(r.Context(), func() { s.Close() })
	}
	s.stopMu.Unlock()
	select {
	case header := <-s.headers:
		if header.err != nil {
			s.Close()
		}
		return header.response, header.err
	case <-r.Context().Done():
		s.Close()
		return nil, r.Context().Err()
	case <-c.done:
		s.Close()
		return nil, errClosed
	}
}
func (c *connection) call(ctx context.Context, cmd command) (result, error) {
	cmd.reply = make(chan result, 1)
	select {
	case c.commands <- cmd:
	case <-ctx.Done():
		return result{}, ctx.Err()
	case <-c.done:
		return result{}, errClosed
	}
	// Once accepted, join before returning a borrowed caller buffer. Context
	// cancellation resets the stream; connection shutdown joins the entire actor.
	select {
	case out := <-cmd.reply:
		return out, nil
	case <-c.done:
		return result{}, errClosed
	}
}
func (s *stream) upload() {
	defer close(s.uploadDone)
	if s.req.Body == nil {
		_, _ = s.conn.call(s.conn.ctx, command{kind: 'f', stream: s})
		return
	}
	defer s.req.Body.Close()
	buffer := make([]byte, chunkSize)
	for {
		n, err := s.req.Body.Read(buffer)
		if n > 0 {
			out, e := s.conn.call(s.conn.ctx, command{kind: 'w', stream: s, data: buffer[:n]})
			if e != nil || out.err != nil {
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				_, _ = s.conn.call(s.conn.ctx, command{kind: 'f', stream: s})
			} else {
				_, _ = s.conn.call(s.conn.ctx, command{kind: 'x', stream: s})
			}
			return
		}
		select {
		case <-s.closed:
			return
		default:
		}
	}
}
func (s *stream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-s.closed:
		s.errorMu.Lock()
		err := s.terminalError
		s.errorMu.Unlock()
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	default:
	}
	out, err := s.conn.call(s.req.Context(), command{kind: 'r', stream: s, data: p[:min(len(p), chunkSize)]})
	if err != nil {
		return 0, err
	}
	if out.err != nil {
		return out.n, out.err
	}
	if out.fin {
		if out.n == 0 {
			s.Close()
			return 0, io.EOF
		}
		return out.n, io.EOF
	}
	return out.n, nil
}
func (s *stream) Close() error {
	s.once.Do(func() {
		close(s.closed)
		s.stopMu.Lock()
		stop := s.stop
		s.stopMu.Unlock()
		if stop != nil {
			stop()
		}
		if s.req.Body != nil {
			s.req.Body.Close()
		}
		_, _ = s.conn.call(s.conn.ctx, command{kind: 'x', stream: s})
		<-s.uploadDone
		s.conn.release()
	})
	return nil
}
func putFields(fields ...string) []byte {
	var out []byte
	for _, v := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	return out
}
func takeFields(p []byte) ([][]byte, error) {
	var fields [][]byte
	for len(p) > 0 {
		if len(p) < 4 {
			return nil, errProtocol
		}
		n := int(binary.BigEndian.Uint32(p))
		p = p[4:]
		if n > len(p) {
			return nil, errProtocol
		}
		fields = append(fields, p[:n])
		p = p[n:]
		if len(fields) > 256 {
			return nil, errProtocol
		}
	}
	return fields, nil
}
func requestMetadata(r *http.Request) ([]byte, error) {
	if r == nil || r.URL == nil || r.URL.Scheme != "https" || !httpguts.ValidHeaderFieldValue(r.Host) || r.Method == "CONNECT" {
		return nil, errors.New("invalid Neqo request")
	}
	method := r.Method
	if method == "" {
		method = "GET"
	}
	if !httpguts.ValidHeaderFieldName(method) {
		return nil, errors.New("invalid method")
	}
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	path := r.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	fields := []string{method, "https", authority, path}
	count := 0
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if lower == "content-length" {
			continue
		} // Request.ContentLength is authoritative.
		if !httpguts.ValidHeaderFieldName(lower) || lower == "connection" || lower == "upgrade" || lower == "transfer-encoding" || lower == "keep-alive" || lower == "proxy-connection" || lower == "host" {
			return nil, errors.New("unsupported Neqo header")
		}
		for _, v := range values {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, errors.New("invalid Neqo header")
			}
			count++
			if count > 128 {
				return nil, errors.New("too many Neqo headers")
			}
			fields = append(fields, lower, v)
		}
	}
	if r.ContentLength > 0 {
		if count == 128 {
			return nil, errors.New("too many Neqo headers")
		}
		fields = append(fields, "content-length", strconv.FormatInt(r.ContentLength, 10))
	}
	metadata := putFields(fields...)
	if len(metadata) > maxHeaders {
		return nil, errors.New("Neqo request headers too large")
	}
	return metadata, nil
}
func (c *connection) verify(data []byte) error {
	encoded, err := takeFields(data)
	if err != nil || len(encoded) == 0 || len(encoded) > 16 {
		return errProtocol
	}
	var certs []*x509.Certificate
	for _, der := range encoded {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return &tls.CertificateVerificationError{Err: err}
		}
		certs = append(certs, cert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	options := x509.VerifyOptions{DNSName: c.name, Roots: c.owner.config.RootCAs, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if c.owner.config.Time != nil {
		options.CurrentTime = c.owner.config.Time()
	}
	chains, err := certs[0].Verify(options)
	if err != nil {
		return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
	}
	state := tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, NegotiatedProtocol: "h3", ServerName: c.name, PeerCertificates: certs, VerifiedChains: chains}
	if verify := c.owner.config.VerifyConnection; verify != nil {
		if err := verify(state); err != nil {
			return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
	}
	c.tlsState = state
	return nil
}
func (s *stream) response(data []byte, fin, interim bool) error {
	fields, err := takeFields(data)
	if err != nil || len(fields)%2 != 0 {
		return errProtocol
	}
	headers := make(http.Header)
	status := 0
	for i := 0; i < len(fields); i += 2 {
		name, value := string(fields[i]), string(fields[i+1])
		if name == ":status" {
			if status != 0 {
				return errProtocol
			}
			status, err = strconv.Atoi(value)
			if err != nil || len(value) != 3 {
				return errProtocol
			}
		} else {
			if strings.HasPrefix(name, ":") || !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
				return errProtocol
			}
			headers.Add(name, value)
		}
	}
	if interim {
		if status < 100 || status >= 200 || status == 101 || fin {
			return errProtocol
		}
		return nil
	}
	if s.headerSeen {
		return nil
	} // Trailers are bounded but not exposed by this prototype.
	if status < 200 || status > 599 {
		return errProtocol
	}
	length := int64(-1)
	if value := headers.Get("Content-Length"); value != "" {
		length, err = strconv.ParseInt(value, 10, 64)
		if err != nil || length < 0 || len(headers.Values("Content-Length")) != 1 {
			return errProtocol
		}
	}
	s.headerSeen = true
	s.recvFin = fin
	state := s.conn.tlsState
	s.headers <- headerResult{response: &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Proto: "HTTP/3.0", ProtoMajor: 3, Header: headers, Body: s, ContentLength: length, Request: s.req, TLS: &state}}
	return nil
}
