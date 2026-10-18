// Package xhttp implements bounded streaming HTTP carriers. It carries bytes,
// not VLESS: FoxTunnel runs its own authenticated HTTP/2 session inside it.
package xhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const Path = "/.well-known/vetroff-xhttp/"
const PairTimeout = 30 * time.Second

var errHandshake = errors.New("XHTTP carrier rejected")

func padding() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return strings.Repeat("X", 100+(int(b[0])<<8|int(b[1]))%901)
}
func headers(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Padding", padding())
}

// Dial creates a detached carrier lifetime only after the HTTP handshake has
// succeeded. A failed/cancelled setup closes every request and pipe. Redirects
// are never followed because the supplied RoundTripper is used directly.
func Dial(ctx context.Context, rt http.RoundTripper, origin, mode, auth, host string) (net.Conn, error) {
	if mode != "xhttp-stream-one" && mode != "xhttp-stream-up" {
		return nil, errHandshake
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errHandshake
	}
	u.Path = Path
	if mode == "xhttp-stream-up" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, err
		}
		id[6] = (id[6] & 15) | 64
		id[8] = (id[8] & 63) | 128
		h := hex.EncodeToString(id[:])
		u.Path += h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	}
	life, cancel := context.WithCancel(context.Background())
	local, peer := net.Pipe()
	c := &carrier{Conn: local, peer: peer, cancel: cancel}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	success := false
	defer func() {
		stop()
		if !success {
			_ = c.Close()
		}
	}()
	request := func(method string, body io.Reader) (*http.Response, error) {
		r, err := http.NewRequestWithContext(life, method, u.String(), body)
		if err != nil {
			return nil, errHandshake
		}
		if host != "" {
			r.Host = host
		}
		r.Header.Set("Proxy-Authorization", auth)
		r.Header.Set("Referer", u.Scheme+"://"+u.Host+Path+"?x_padding="+padding())
		if method == "POST" {
			r.Header.Set("Content-Type", "application/grpc")
		}
		resp, err := rt.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, errHandshake
		}
		return resp, nil
	}
	// NopCloser avoids net/http closing the shared duplex pipe when it finishes
	// reading the upload. Only carrier.Close owns the pipe and request lifetime.
	up, err := request("POST", io.NopCloser(peer))
	if err != nil {
		return nil, err
	}
	down := up
	if mode == "xhttp-stream-up" {
		go func() {
			_, _ = io.Copy(io.Discard, up.Body)
			_ = up.Body.Close()
			_ = c.Close()
		}()
		down, err = request("GET", nil)
		if err != nil {
			return nil, err
		}
	}
	if ctx.Err() != nil {
		down.Body.Close()
		return nil, ctx.Err()
	}
	go func() {
		_, _ = io.Copy(peer, down.Body)
		_ = down.Body.Close()
		_ = c.Close()
	}()
	success = true
	return c, nil
}

type carrier struct {
	net.Conn
	peer   net.Conn
	cancel context.CancelFunc
	once   sync.Once
}

func (c *carrier) Close() error {
	c.once.Do(func() { c.cancel(); _ = c.peer.Close(); _ = c.Conn.Close() })
	return nil
}

// Server must not be copied after use. Authentication is required before any
// state allocation. Unpaired carriers expire and do not spawn application work.
type Server struct {
	MaxSessions int
	Authorized  func(*http.Request) bool
	ServeConn   func(net.Conn, *http.Request)
	mu          sync.Mutex
	sessions    map[string]*session
	active      int
}
type session struct {
	local, peer      net.Conn
	upload, download bool // guarded by Server.mu
	done             chan struct{}
	once             sync.Once
	timer            *time.Timer
}

func (s *Server) close(id string, p *session) {
	p.once.Do(func() {
		_ = p.local.Close()
		_ = p.peer.Close()
		s.mu.Lock()
		if p.timer != nil {
			p.timer.Stop()
		}
		if id != "" {
			delete(s.sessions, id)
		}
		s.active--
		s.mu.Unlock()
		close(p.done)
	})
}
func (s *Server) claim(id string, upload bool) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.sessions[id]
	if id == "" {
		p = nil
	}
	if p == nil {
		limit := s.MaxSessions
		if limit <= 0 {
			limit = 256
		}
		if s.active >= limit {
			return nil, false
		}
		a, b := net.Pipe()
		p = &session{local: a, peer: b, done: make(chan struct{})}
		s.active++
		if id != "" {
			if s.sessions == nil {
				s.sessions = make(map[string]*session)
			}
			s.sessions[id] = p
			p.timer = time.AfterFunc(PairTimeout, func() { s.close(id, p) })
		}
	}
	if upload {
		if p.upload {
			return nil, false
		}
		p.upload = true
	} else {
		if p.download {
			return nil, false
		}
		p.download = true
	}
	if p.upload && p.download && p.timer != nil {
		p.timer.Stop()
	}
	return p, true
}

func validID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(id, "-", "")
	_, err := hex.DecodeString(raw)
	return err == nil && strings.ToLower(id) == id
}

// Matches rejects escaped separators, query strings and ambiguous spellings.
func Matches(r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, Path) || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		return false
	}
	tail := strings.TrimPrefix(r.URL.Path, Path)
	return tail == "" || validID(tail)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !Matches(r) || r.ProtoMajor != 2 || s.Authorized == nil || !s.Authorized(r) || (r.Method != "GET" && r.Method != "POST") {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, Path)
	upload := r.Method == "POST"
	if id == "" && !upload {
		http.NotFound(w, r)
		return
	}
	p, ok := s.claim(id, upload)
	if !ok {
		http.Error(w, "server busy", http.StatusServiceUnavailable)
		return
	}
	defer s.close(id, p)
	stop := context.AfterFunc(r.Context(), func() { s.close(id, p) })
	defer stop()
	headers(w)
	w.WriteHeader(http.StatusOK)
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}
	f.Flush()
	if id == "" || !upload {
		// Only the downstream owns application execution. For stream-one, upload
		// and download belong to the same request; for stream-up they are separate.
		go func() { s.ServeConn(p.local, r); s.close(id, p) }()
	}
	if id == "" || upload {
		copied := make(chan struct{})
		go func() { _, _ = io.Copy(p.peer, r.Body); s.close(id, p); close(copied) }()
		defer func() { _ = r.Body.Close(); <-copied }()
	}
	if id == "" || !upload {
		_, _ = io.Copy(flushWriter{w, f}, p.peer)
		return
	}
	// Padding on the unused upload response keeps intermediaries from treating
	// the stream as idle. These bytes never enter the application byte stream.
	timer := time.NewTicker(25 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-timer.C:
			if _, err := fmt.Fprint(w, padding()); err != nil {
				return
			}
			f.Flush()
		}
	}
}

type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (w flushWriter) Write(p []byte) (int, error) { n, err := w.w.Write(p); w.f.Flush(); return n, err }
