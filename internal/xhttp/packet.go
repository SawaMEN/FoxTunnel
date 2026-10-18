package xhttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// At most eight reserved payloads per carrier, including reads in progress and
// the block currently being delivered. The client emits 32 KiB blocks. These
// conservative limits intentionally differ from Xray's configurable defaults.
const MaxPacketBytes = 64 << 10
const MaxPendingPackets = 8
const clientPacketBytes = 32 << 10

type packet struct {
	data      []byte
	ready     bool
	delivered chan struct{}
}

func parsePath(r *http.Request) (id string, seq *uint64, ok bool) {
	if !strings.HasPrefix(r.URL.Path, Path) || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return "", nil, false
	}
	tail := strings.TrimPrefix(r.URL.Path, Path)
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
	data, err := io.ReadAll(io.LimitReader(r.Body, MaxPacketBytes+1))
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
	// ACK only after ordered delivery so a sequential sender naturally observes
	// application backpressure and cannot fill the bounded reorder window.
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
	r, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, errHandshake
	}
	if host != "" {
		r.Host = host
	}
	r.Header.Set("Proxy-Authorization", auth)
	r.Header.Set("Referer", u.Scheme+"://"+u.Host+Path+"?x_padding="+padding())
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
func sendPackets(c *carrier, ctx context.Context, rt http.RoundTripper, u *url.URL, auth, host string) {
	defer c.Close()
	buffer := make([]byte, clientPacketBytes)
	var seq uint64
	for {
		n, err := c.peer.Read(buffer)
		if n > 0 {
			dest := *u
			dest.Path += "/" + strconv.FormatUint(seq, 10)
			attempt, cancel := context.WithTimeout(ctx, PairTimeout)
			// Do not set GetBody: automatic HTTP replay after an ambiguous ACK is unsafe.
			resp, sendErr := sendRequest(attempt, rt, &dest, "POST", packetBody{bytes.NewReader(buffer[:n])}, auth, host, false)
			if sendErr == nil {
				_, sendErr = io.Copy(io.Discard, io.LimitReader(resp.Body, 4097))
				_ = resp.Body.Close()
			}
			cancel()
			if sendErr != nil || seq == ^uint64(0) {
				return
			}
			seq++
		}
		if err != nil {
			return
		}
	}
}

// Hide the concrete bytes.Reader type from NewRequest so GetBody stays nil.
type packetBody struct{ *bytes.Reader }
