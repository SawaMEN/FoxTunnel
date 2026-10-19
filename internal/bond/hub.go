// Package bond is an experimental bounded multi-node byte-stream carrier.
// The HTTPS/authentication layer is supplied by internal/tunnel. It is not MPQUIC.
package bond

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const Path = "/.well-known/foxtunnel-bond-v1"
const chunkSize = 32 << 10
const window = 8
const lifetime = 2 * time.Minute
const headerSize = 49 // operation, 32-byte token, sequence, cumulative download ACK
const (
	opOpen byte = iota
	opWrite
	opRead
	opFin
	opClose
)

type block struct {
	data  []byte
	eof   bool
	lanes bool
}
type session struct {
	mu                        sync.Mutex
	changed                   chan struct{}
	ready                     chan struct{}
	idle                      *time.Timer
	stopOwner                 func() bool
	target                    string
	conn                      net.Conn
	err                       error
	closed                    bool
	touched                   time.Time
	nextUp, nextDown, ackDown uint64
	up, down                  map[uint64]block
	receiveBuffers            [window][]byte
	lanes                     map[io.ReadCloser]struct{}
}

func (s *session) signal() { close(s.changed); s.changed = make(chan struct{}) }
func (s *session) stop(err error) {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		if s.stopOwner != nil {
			s.stopOwner()
		}
		for body := range s.lanes {
			body.Close()
		}
		s.up = nil
		s.down = nil
		s.receiveBuffers = [window][]byte{}
		if s.idle != nil {
			s.idle.Stop()
		}
		s.err = err
		if s.conn != nil {
			s.conn.Close()
		}
		s.signal()
	}
	s.mu.Unlock()
}

type Hub struct {
	identityOnce   sync.Once
	identity       [32]byte
	identityError  error
	Dial           func(context.Context, string) (net.Conn, error)
	Owner          func(context.Context) string
	SessionContext func(context.Context) context.Context
	MaxSessions    int
	mu             sync.Mutex
	sessions       map[string]*session
	lastSweep      time.Time
	closed         bool
}

// Tokens contain creation time and 192 random bits. Expired opens are rejected,
// while tombstones outlive the entire open retry window, preventing redial/replay.
func validToken(token []byte, now time.Time) bool {
	created := time.Unix(int64(binary.BigEndian.Uint64(token[:8])), 0)
	return !created.After(now.Add(5*time.Second)) && now.Sub(created) < 30*time.Second
}
func (h *Hub) get(ctx context.Context, token []byte, target string) (*session, error) {
	now := time.Now()
	key := hex.EncodeToString(token)
	if h.Owner != nil {
		key = h.Owner(ctx) + ":" + key
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, net.ErrClosed
	}
	if h.sessions == nil {
		h.sessions = make(map[string]*session)
	}
	// Lazy cleanup has no background timer and retains closed-session tombstones.
	if now.Sub(h.lastSweep) > 5*time.Second {
		h.lastSweep = now
		for k, s := range h.sessions {
			s.mu.Lock()
			stale := now.Sub(s.touched) > lifetime
			s.mu.Unlock()
			if stale {
				s.stop(net.ErrClosed)
				delete(h.sessions, k)
			}
		}
	}

	s := h.sessions[key]
	if s != nil {
		h.mu.Unlock()
		if target != "" && s.target != target {
			return nil, errors.New("session target mismatch")
		}
		select {
		case <-s.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return s, nil
	}
	if target == "" || !validToken(token, now) {
		h.mu.Unlock()
		return nil, errors.New("unknown or expired session")
	}
	maxSessions := h.MaxSessions
	if maxSessions <= 0 {
		maxSessions = 256
	}
	active := 0
	for _, existing := range h.sessions {
		existing.mu.Lock()
		if !existing.closed {
			active++
		}
		existing.mu.Unlock()
	}
	if active >= maxSessions || len(h.sessions) >= 4096 {
		h.mu.Unlock()
		return nil, errors.New("session capacity reached")
	}
	s = &session{target: target, changed: make(chan struct{}), ready: make(chan struct{}), touched: now, up: make(map[uint64]block), down: make(map[uint64]block)}
	s.idle = time.AfterFunc(lifetime, func() { s.stop(context.DeadlineExceeded) })
	sessionCtx := context.Background()
	if h.SessionContext != nil {
		sessionCtx = h.SessionContext(ctx)
	}
	stopOwner := context.AfterFunc(sessionCtx, func() { s.stop(context.Canceled) })
	s.mu.Lock()
	if s.closed {
		stopOwner()
	} else {
		s.stopOwner = stopOwner
	}
	s.mu.Unlock()
	h.sessions[key] = s
	h.mu.Unlock()
	// Dial belongs to the session, not the first HTTP attempt; losing that attempt
	// cannot create a second destination connection on a retry through another node.
	go func() {
		dialCtx, cancel := context.WithTimeout(sessionCtx, 10*time.Second)
		defer cancel()
		conn, err := h.Dial(dialCtx, target)
		s.mu.Lock()
		if s.closed {
			if conn != nil {
				conn.Close()
			}
			err = net.ErrClosed
		}
		s.conn = conn
		s.err = err
		s.closed = err != nil
		if err != nil {
			if s.stopOwner != nil {
				s.stopOwner()
			}
			if s.idle != nil {
				s.idle.Stop()
			}
		}
		close(s.ready)
		s.signal()
		s.mu.Unlock()
		if err == nil {
			go s.upload()
			go s.download()
		}
	}()
	select {
	case <-s.ready:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Identity binds discovery and all entry paths to this running common exit.
func (h *Hub) Identity() (string, error) {
	h.identityOnce.Do(func() { _, h.identityError = rand.Read(h.identity[:]) })
	return hex.EncodeToString(h.identity[:]), h.identityError
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = h.Identity()
	if h.identityError != nil {
		http.Error(w, "hub initialization failed", 503)
		return
	}
	expected := r.Header.Get("X-FoxTunnel-Bond-Hub")
	if expected != "" && expected != hex.EncodeToString(h.identity[:]) {
		http.Error(w, "different hub", 409)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get(LaneHeader) == LaneVersion {
		h.serveLane(w, r)
		return
	}
	body, err := readBounded(r.Body, r.ContentLength, headerSize+chunkSize)
	if err != nil || len(body) < headerSize || len(body) > headerSize+chunkSize {
		http.Error(w, "bad frame", 400)
		return
	}
	h.serveFrame(w, r, body)
}

func (h *Hub) serveFrame(w http.ResponseWriter, r *http.Request, body []byte) {
	expected := r.Header.Get("X-FoxTunnel-Bond-Hub")
	op, token := body[0], body[1:33]
	seq := binary.BigEndian.Uint64(body[33:41])
	ack := binary.BigEndian.Uint64(body[41:49])
	payload := body[49:]
	if op > opClose || (op != opOpen && op != opWrite && len(payload) != 0) || (op == opWrite && len(payload) == 0) {
		http.Error(w, "bad operation", 400)
		return
	}
	if op != opOpen && expected == "" {
		http.Error(w, "missing hub identity", 409)
		return
	}
	target := ""
	if op == opOpen {
		target = string(payload)
		if len(target) == 0 || len(target) > 512 {
			http.Error(w, "bad target", 400)
			return
		}
	}
	s, err := h.get(r.Context(), token, target)
	if err != nil {
		http.Error(w, "session unavailable", 409)
		return
	}
	if op == opClose {
		s.stop(net.ErrClosed)
		w.WriteHeader(200)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touched = time.Now()
	if s.idle != nil && !s.closed {
		s.idle.Reset(lifetime)
	}
	if s.closed {
		http.Error(w, "session closed", 410)
		return
	}
	wait := time.Second
	if requested, err := time.ParseDuration(r.Header.Get("X-FoxTunnel-Bond-Wait")); err == nil {
		wait = max(20*time.Millisecond, min(time.Second, requested))
	}
	switch op {
	case opOpen:
		w.Header().Set(LaneHeader, LaneVersion)
		w.WriteHeader(200)
		w.Write(h.identity[:])
	case opWrite, opFin:
		if seq < s.nextUp {
			w.WriteHeader(200)
			return
		} // Already delivered: never write twice.
		if seq-s.nextUp >= window {
			http.Error(w, "send window full", 429)
			return
		}
		value := block{data: payload, eof: op == opFin}
		if previous, ok := s.up[seq]; ok {
			if previous.eof != value.eof || !bytes.Equal(previous.data, value.data) {
				http.Error(w, "conflicting duplicate", 409)
				return
			}
		} else {
			s.up[seq] = value
			s.signal()
		}
		// Confirm only after the shared writer has delivered the block to the
		// one destination socket. A timed-out HTTP attempt can safely retry it.
		timer := time.NewTimer(wait)
		defer timer.Stop()
		for s.nextUp <= seq {
			if s.closed {
				http.Error(w, "session closed", 410)
				return
			}
			changed := s.changed
			s.mu.Unlock()
			select {
			case <-changed:
			case <-timer.C:
				s.mu.Lock()
				w.WriteHeader(204)
				return
			case <-r.Context().Done():
				s.mu.Lock()
				w.WriteHeader(http.StatusRequestTimeout)
				return
			}
			s.mu.Lock()
		}
		w.WriteHeader(200)
	case opRead:
		if ack > s.nextDown || ack < s.ackDown { // A stale concurrent ACK is harmless.
			if ack > s.nextDown {
				http.Error(w, "invalid acknowledgement", 400)
				return
			}
		} else {
			for i := s.ackDown; i < ack; i++ {
				delete(s.down, i)
			}
			s.ackDown = ack
			s.signal()
		}
		if seq < s.ackDown || seq-s.ackDown >= window {
			http.Error(w, "invalid receive window", 409)
			return
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		for {
			if b, ok := s.down[seq]; ok {
				if b.eof {
					w.WriteHeader(201)
				} else {
					w.WriteHeader(200)
					w.Write(b.data)
				}
				return
			}
			if s.closed {
				http.Error(w, "session closed", 410)
				return
			}
			changed := s.changed
			s.mu.Unlock()
			select {
			case <-changed:
			case <-timer.C:
				s.mu.Lock()
				w.WriteHeader(204)
				return
			case <-r.Context().Done():
				s.mu.Lock()
				w.WriteHeader(http.StatusRequestTimeout)
				return
			}
			s.mu.Lock()
		}
	}
}
func (s *session) upload() {
	for {
		s.mu.Lock()
		var b block
		for {
			if s.closed {
				s.mu.Unlock()
				return
			}
			var ok bool
			b, ok = s.up[s.nextUp]
			if ok {
				break
			}
			changed := s.changed
			s.mu.Unlock()
			<-changed
			s.mu.Lock()
		}
		s.mu.Unlock()
		if b.eof {
			if tcp, ok := s.conn.(interface{ CloseWrite() error }); ok {
				if err := tcp.CloseWrite(); err != nil {
					s.stop(err)
					return
				}
			}
		} else {
			if _, err := io.Copy(s.conn, bytes.NewReader(b.data)); err != nil {
				s.stop(err)
				return
			}
		}
		s.mu.Lock()
		delete(s.up, s.nextUp)
		s.nextUp++
		s.signal()
		s.mu.Unlock()
		if b.eof {
			return
		}
	}
}
func (s *session) download() {
	for {
		s.mu.Lock()
		for !s.closed && s.nextDown-s.ackDown >= window {
			changed := s.changed
			s.mu.Unlock()
			<-changed
			s.mu.Lock()
		}
		if s.closed {
			s.mu.Unlock()
			return
		}
		slot := s.nextDown % window
		if s.receiveBuffers[slot] == nil {
			s.receiveBuffers[slot] = make([]byte, chunkSize)
		}
		buf := s.receiveBuffers[slot]
		s.mu.Unlock()
		n, err := s.conn.Read(buf)
		if n > 0 {
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}
			s.down[s.nextDown] = block{data: buf[:n]}
			s.nextDown++
			s.signal()
			s.mu.Unlock()
		}
		if err != nil {
			if err != io.EOF {
				s.stop(err)
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}
			s.down[s.nextDown] = block{eof: true}
			s.nextDown++
			s.signal()
			s.mu.Unlock()
			return
		}
	}
}
func (h *Hub) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for _, s := range h.sessions {
		s.stop(net.ErrClosed)
	}
	return nil
}
