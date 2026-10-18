package xhttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// At most eight reserved payloads per carrier, including reads in progress and
// the block currently being delivered. The client emits 32 KiB blocks. These
// conservative limits intentionally differ from Xray's configurable defaults.
const MaxPacketBytes = 64 << 10
const MaxPendingPackets = 8
const clientPacketBytes = 32 << 10
const clientPacketWindow = 4

type packet struct {
	data      []byte
	ready     bool
	delivered chan struct{}
}

func parsePath(r *http.Request) (id string, seq *uint64, ok bool) { return parsePathAt(r, Path) }
func parsePathAt(r *http.Request, prefix string) (id string, seq *uint64, ok bool) {
	if !strings.HasPrefix(r.URL.Path, prefix) || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return "", nil, false
	}
	tail := strings.TrimPrefix(r.URL.Path, prefix)
	if tail == "" {
		return "", nil, true
	}
	id, raw, hasSeq := strings.Cut(tail, "/")
	if !validID(id) {
		return "", nil, false
	}
	if !hasSeq {
		return id, nil, true
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != raw {
		return "", nil, false
	}
	return id, &n, true
}

func (s *Server) admitPacket(id string, seq uint64) (*session, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.getSessionLocked(id)
	if p == nil {
		return nil, http.StatusServiceUnavailable
	}
	if p.mode == "stream" || seq < p.next || seq-p.next >= MaxPendingPackets || p.pending[seq] != nil {
		return nil, http.StatusConflict
	}
	if p.pending == nil {
		p.pending = make(map[uint64]*packet)
	}
	if len(p.pending) >= MaxPendingPackets {
		return nil, http.StatusTooManyRequests
	}
	p.pending[seq] = &packet{delivered: make(chan struct{})}
	if p.mode == "" {
		p.mode = "packet"
		p.upload = true
		go s.deliverPackets(id, p)
	}
	if p.download && p.timer != nil {
		p.timer.Stop()
	}
	p.signalLocked()
	return p, 0
}
func (p *session) signalLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (s *Server) servePacket(w http.ResponseWriter, r *http.Request, id string, seq uint64) {
	p, status := s.admitPacket(id, seq)
	if status != 0 {
		http.Error(w, "packet rejected", status)
		return
	}
	// A stalled/truncated body cannot keep a reservation beyond session expiry.
	stopBody := context.AfterFunc(p.ctx, func() { _ = r.Body.Close() })
	defer stopBody()
	stopRequest := context.AfterFunc(r.Context(), func() { s.close(id, p) })
	defer stopRequest()
	// Bound each body independently: an earlier block may be legitimately stuck
	// in application backpressure, so the reorder worker cannot own this timer.
	readTimer := time.AfterFunc(PairTimeout, func() { s.close(id, p) })
	data, err := readPacket(r)
	readTimer.Stop()
	if err != nil || len(data) > MaxPacketBytes {
		s.close(id, p)
		http.Error(w, "invalid packet", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if p.ctx.Err() != nil {
		s.mu.Unlock()
		http.Error(w, "session closed", http.StatusGone)
		return
	}
	item := p.pending[seq]
	item.data = data
	item.ready = true
	p.signalLocked()
	s.mu.Unlock()
	// ACK only after ordered delivery so the bounded client window observes
	// application backpressure instead of acknowledging queued bytes.
	select {
	case <-item.delivered:
	case <-p.done:
		select {
		case <-item.delivered:
		default:
			http.Error(w, "session closed", http.StatusGone)
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Padding", padding())
	w.WriteHeader(http.StatusOK)
}

func (s *Server) deliverPackets(id string, p *session) {
	defer s.close(id, p)
	var gapDeadline time.Time
	for {
		s.mu.Lock()
		item := p.pending[p.next]
		if item != nil && item.ready {
			seq := p.next
			s.mu.Unlock()
			// Keep the reservation until delivery completes, including partial writes.
			if _, err := io.Copy(p.peer, bytes.NewReader(item.data)); err != nil {
				return
			}
			s.mu.Lock()
			delete(p.pending, seq)
			close(item.delivered)
			if p.next == ^uint64(0) {
				s.mu.Unlock()
				return
			}
			p.next++
			s.mu.Unlock()
			gapDeadline = time.Time{}
			continue
		}
		changed := p.changed
		waiting := len(p.pending) > 0
		s.mu.Unlock()
		if !waiting {
			gapDeadline = time.Time{}
			select {
			case <-p.done:
				return
			case <-changed:
				continue
			}
		}
		if gapDeadline.IsZero() {
			gapDeadline = time.Now().Add(PairTimeout)
		}
		timer := time.NewTimer(time.Until(gapDeadline))
		select {
		case <-p.done:
			timer.Stop()
			return
		case <-timer.C:
			return
		case <-changed:
			timer.Stop()
		}
	}
}

func sendRequest(ctx context.Context, rt http.RoundTripper, u *url.URL, method string, body io.Reader, auth, host string, streaming bool) (*http.Response, error) {
	return sendRequestAt(ctx, rt, u, method, body, auth, host, streaming, Path)
}
func sendRequestAt(ctx context.Context, rt http.RoundTripper, u *url.URL, method string, body io.Reader, auth, host string, streaming bool, prefix string) (*http.Response, error) {
	r, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, errHandshake
	}
	if host != "" {
		r.Host = host
	}
	r.Header.Set("Proxy-Authorization", auth)
	r.Header.Set("Referer", u.Scheme+"://"+r.Host+prefix+"?x_padding="+padding())
	if method == "POST" {
		r.Header.Set("Content-Type", "application/octet-stream")
		if streaming {
			r.Header.Set("Content-Type", "application/grpc")
		}
	}
	if sized, ok := body.(interface{ Len() int }); ok && method == "POST" {
		r.ContentLength = int64(sized.Len())
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

// readPacket allocates once for the known-size POSTs emitted by our client.
// Unknown-size bodies retain bounded legacy handling. Always check EOF, since
// custom transports and tests may not enforce the declared Content-Length.
func readPacket(r *http.Request) ([]byte, error) {
	if r.ContentLength < 0 {
		return io.ReadAll(io.LimitReader(r.Body, MaxPacketBytes+1))
	}
	if r.ContentLength > MaxPacketBytes {
		return nil, errHandshake
	}
	data := make([]byte, int(r.ContentLength))
	if _, err := io.ReadFull(r.Body, data); err != nil {
		return nil, err
	}
	var extra [1]byte
	if _, err := io.ReadFull(r.Body, extra[:]); err != io.EOF {
		return nil, errHandshake
	}
	return data, nil
}

type packetResult struct {
	seq uint64
	err error
}
type outgoingPacket struct {
	buffer       []byte
	acknowledged bool
}

func sendPacketsWindow(c *carrier, ctx context.Context, rt http.RoundTripper, u *url.URL, auth, host, prefix string, window int) {
	var workers sync.WaitGroup
	// Cancellation must happen before waiting, including a worker whose ACK is
	// stuck. Results are buffered for the complete bounded window during teardown.
	defer func() { _ = c.Close(); workers.Wait() }()
	results := make(chan packetResult, window)
	slots := make([]outgoingPacket, window)
	for i := range slots {
		slots[i].buffer = make([]byte, clientPacketBytes)
	}
	var base, next uint64
	record := func(result packetResult) bool {
		if result.err != nil {
			return false
		}
		slots[result.seq%uint64(window)].acknowledged = true
		// Reuse a slot only when all preceding ACKs have arrived. A later ACK must
		// not advance the sequence window past a missing earlier acknowledgement.
		for base < next && slots[base%uint64(window)].acknowledged {
			slots[base%uint64(window)].acknowledged = false
			base++
		}
		return true
	}
	for {
		for next-base >= uint64(window) {
			select {
			case result := <-results:
				if !record(result) {
					return
				}
			case <-ctx.Done():
				return
			}
		}
		slot := &slots[next%uint64(window)]
		n, readErr := c.peer.Read(slot.buffer)
		if n > 0 {
			seq := next
			written := make(chan struct{})
			workers.Add(1)
			go func(payload []byte) {
				defer workers.Done()
				var once sync.Once
				var writeErr error
				finishWrite := func(err error) { once.Do(func() { writeErr = err; close(written) }) }
				attempt, cancel := context.WithTimeout(ctx, PairTimeout)
				defer cancel()
				// WroteRequest runs only after the complete body was written. Start the
				// next POST at that boundary, without waiting for the previous response.
				trace := &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
					if info.Err != nil {
						_ = c.Close()
					}
					finishWrite(info.Err)
				}}
				attempt = httptrace.WithClientTrace(attempt, trace)
				dest := *u
				dest.Path += "/" + strconv.FormatUint(seq, 10)
				// GetBody stays nil: no automatic replay after an ambiguous ACK.
				body := &ownedPacketBody{reader: bytes.NewReader(payload)}
				resp, err := sendRequestAt(attempt, rt, &dest, "POST", body, auth, host, false, prefix)
				if err != nil {
					finishWrite(err)
				} else {
					// A peer can send headers before it reads the upload. Its
					// response must not release the payload while a writer still
					// owns it; require successful completion of the request body.
					select {
					case <-written:
						err = writeErr
					case <-attempt.Done():
						err = attempt.Err()
						finishWrite(err)
					}
				}
				if err == nil {
					var count int64
					count, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4097))
					_ = resp.Body.Close()
					if count > 4096 {
						err = errHandshake
					}
				}
				if resp != nil {
					_ = resp.Body.Close()
				}
				_ = body.Close()
				if err != nil {
					_ = c.Close()
				}
				results <- packetResult{seq: seq, err: err}
			}(slot.buffer[:n])
			next++
			select {
			case <-written:
			case <-ctx.Done():
				return
			}
			if seq == ^uint64(0) {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

// Hide the concrete bytes.Reader type from NewRequest so GetBody stays nil.
type packetBody struct{ *bytes.Reader }

// Close synchronizes with any outstanding body read, including a transport
// which returns an early response. No stale writer may read a reused buffer.
type ownedPacketBody struct {
	mu     sync.Mutex
	reader *bytes.Reader
	closed bool
}

func (b *ownedPacketBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, io.ErrClosedPipe
	}
	return b.reader.Read(p)
}
func (b *ownedPacketBody) Len() int     { b.mu.Lock(); defer b.mu.Unlock(); return b.reader.Len() }
func (b *ownedPacketBody) Close() error { b.mu.Lock(); b.closed = true; b.mu.Unlock(); return nil }
