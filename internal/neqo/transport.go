//go:build neqo && cgo && linux && amd64

package neqo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
)

const (
	maxOrigins  = 8
	maxStreams  = 32
	chunkSize   = 32 << 10
	maxMetadata = 1 << 20
	idleRetire  = 25 * time.Second // below the pinned Neqo QUIC 30s idle timeout
)

type transport struct {
	config   *tls.Config
	timeout  time.Duration
	mu       sync.Mutex
	origins  map[string]*connection
	live     map[*connection]struct{} // includes draining/evicted native engines
	sessions map[string]session
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
	draining           atomic.Bool
	peerDER            []byte
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
	sendStopped              bool // actor-owned upload direction
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
	return &transport{config: config.TLS.Clone(), timeout: timeout, origins: make(map[string]*connection), live: make(map[*connection]struct{})}, nil
}
func newEngineCheck() (bool, error) {
	if err := checkABI(); err != nil {
		return false, err
	}
	return true, nil
}

// acquire never reuses a draining or expired native engine. A retired engine
// may continue serving existing requests; live counts it until actor teardown.
// When capacity is full, wait for one idle engine to stop rather than exceed
// maxOrigins with overlapping old/new QUIC connections.
func (t *transport) acquire(ctx context.Context, u *url.URL) (*connection, error) {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" {
		return nil, errors.New("Neqo requires an HTTPS origin")
	}
	key := u.Scheme + "://" + u.Host
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		t.mu.Lock()
		c := t.origins[key]
		if c != nil {
			select {
			case <-c.done:
				delete(t.origins, key)
				c = nil
			default:
			}
		}
		if c != nil && (c.draining.Load() || (c.active == 0 && time.Since(c.touched) >= idleRetire)) {
			c.draining.Store(true)
			delete(t.origins, key)
			if c.active == 0 {
				c.cancel()
			}
			c = nil
		}
		if c == nil {
			if len(t.live) >= maxOrigins {
				// Evict an idle engine only. Draining active streams must
				// not be killed to make room for new connections.
				var oldest *connection
				for candidate := range t.live {
					if candidate.active == 0 && (oldest == nil || candidate.touched.Before(oldest.touched)) {
						oldest = candidate
					}
				}
				if oldest == nil {
					t.mu.Unlock()
					return nil, ErrCapacity
				}
				oldest.draining.Store(true)
				if t.origins[oldest.origin] == oldest {
					delete(t.origins, oldest.origin)
				}
				oldest.cancel()
				t.mu.Unlock()
				select {
				case <-oldest.done:
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			port := u.Port()
			if port == "" {
				port = "443"
			}
			name := t.config.ServerName
			if name == "" {
				name = u.Hostname()
			}
			connCtx, cancel := context.WithCancel(context.Background())
			c = &connection{
				owner: t, origin: key, addr: net.JoinHostPort(u.Hostname(), port),
				name: name, ctx: connCtx, cancel: cancel, ready: make(chan struct{}),
				done: make(chan struct{}), commands: make(chan command, 2*maxStreams),
			}
			c.touched = time.Now()
			t.origins[key] = c
			t.live[c] = struct{}{}
			go c.run()
		}
		if c.active >= maxStreams {
			t.mu.Unlock()
			return nil, ErrCapacity
		}
		c.active++
		c.touched = time.Now()
		t.mu.Unlock()
		return c, nil
	}
}

func (c *connection) release() {
	c.owner.mu.Lock()
	c.active--
	c.touched = time.Now()
	if c.active == 0 && c.draining.Load() {
		c.cancel()
	}
	c.owner.mu.Unlock()
}

// retire stops new HTTP/3 streams after GOAWAY but leaves existing streams
// alive until their request/response bodies finish. No request is replayed.
func (t *transport) retire(c *connection) {
	t.mu.Lock()
	c.draining.Store(true)
	if t.origins[c.origin] == c {
		delete(t.origins, c.origin)
	}
	if c.active == 0 {
		c.cancel()
	}
	t.mu.Unlock()
}

// forget is called after the actor's native engine and UDP reader are closed.
// Keep live independent of origin keys to bound overlapping draining engines.
func (t *transport) forget(c *connection) {
	t.mu.Lock()
	delete(t.live, c)
	if t.origins[c.origin] == c {
		delete(t.origins, c.origin)
	}
	t.mu.Unlock()
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
	c, err := t.acquire(ctx, u)
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
	for c := range t.live {
		if c.active == 0 {
			c.draining.Store(true)
			if t.origins[c.origin] == c {
				delete(t.origins, c.origin)
			}
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
	// A GOAWAY that races the first stream creation may be retried on a
	// fresh engine once. No HTTP stream exists at that point and the
	// request body remains unread. A broken in-flight stream is never
	// replayed, even when its error looks like a network failure.
	for attempt := 0; attempt < 2; attempt++ {
		c, err := t.acquire(r.Context(), r.URL)
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
		out, callErr := c.call(r.Context(), command{kind: 'o', stream: s, data: metadata})
		if callErr != nil || out.err != nil {
			c.release()
			if callErr == nil && errors.Is(out.err, errDraining) && attempt == 0 && r.Context().Err() == nil {
				continue
			}
			return nil, errors.Join(callErr, out.err)
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
	return nil, errDraining
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
				_, _ = s.conn.call(s.conn.ctx, command{kind: 'a', stream: s})
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
		// Deliver the final bytes without signaling EOF in the same
		// call. The next Read returns EOF and releases the stream.
		return out.n, nil
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
func (c *connection) verify(data []byte) error {
	return c.verifySession(data, false)
}
func (c *connection) verifySession(data []byte, resumed bool) error {
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
	state := tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, DidResume: resumed, NegotiatedProtocol: "h3", ServerName: c.name, PeerCertificates: certs, VerifiedChains: chains}
	if verify := c.owner.config.VerifyConnection; verify != nil {
		if err := verify(state); err != nil {
			return &tls.CertificateVerificationError{UnverifiedCertificates: certs, Err: err}
		}
	}
	c.tlsState = state
	c.peerDER = append(c.peerDER[:0], data...)
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
