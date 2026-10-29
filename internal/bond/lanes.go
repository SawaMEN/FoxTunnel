package bond

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"
)

// LaneHeader advertises and requests bounded duplex record exchange.
// Old hubs/relays omit the capability and retain per-record RPC.
const LaneHeader = "X-Vetroff-Bond-Lane"
const LaneVersion = "records-v1"

var errLaneUnsupported = errors.New("bond lane negotiation unavailable")

func (h *Hub) serveLane(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 && r.ProtoMajor != 3 || r.Header.Get("X-Vetroff-Bond-Hub") == "" {
		http.Error(w, "lane requires verified hub and h2/h3", 400)
		return
	}
	idle := time.AfterFunc(lifetime, func() { r.Body.Close() })
	defer idle.Stop()
	var token [32]byte
	if _, err := io.ReadFull(r.Body, token[:]); err != nil {
		http.Error(w, "bad lane binding", 400)
		return
	}
	s, err := h.get(r.Context(), token[:], "")
	if err != nil {
		http.Error(w, "session unavailable", 409)
		return
	}
	s.mu.Lock()
	if s.closed || len(s.lanes) >= 2*window {
		s.mu.Unlock()
		http.Error(w, "lane capacity reached", 429)
		return
	}
	if s.lanes == nil {
		s.lanes = make(map[io.ReadCloser]struct{})
	}
	s.lanes[r.Body] = struct{}{}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.lanes, r.Body); s.mu.Unlock() }()
	// Idle bodies cannot retain an authenticated handler forever. Session stop
	// also closes every lane; an active record refreshes the session timer.
	w.Header().Set(LaneHeader, LaneVersion)
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	reply := &laneReply{header: make(http.Header)}
	for {
		var size [8]byte
		if _, err := io.ReadFull(r.Body, size[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(size[:4])
		if n < headerSize || n > headerSize+chunkSize {
			return
		}
		// Ownership transfers to the bounded session upload map until destination
		// delivery. Never reuse a record buffer after a timed-out acknowledgement.
		frame := make([]byte, int(n))
		if _, err := io.ReadFull(r.Body, frame); err != nil {
			return
		}
		if !bytes.Equal(frame[1:33], token[:]) || frame[0] == opOpen || frame[0] == opClose {
			return
		}
		idle.Reset(lifetime)
		wait := time.Duration(binary.BigEndian.Uint32(size[4:])) * time.Millisecond
		r.Header.Set("X-Vetroff-Bond-Wait", max(20*time.Millisecond, min(time.Second, wait)).String())
		reply.status = 0
		reply.data = reply.data[:0]
		clear(reply.header)
		h.serveFrame(reply, r, frame)
		var header [6]byte
		binary.BigEndian.PutUint16(header[:2], uint16(reply.status))
		binary.BigEndian.PutUint32(header[2:], uint32(len(reply.data)))
		if writeFull(w, header[:]) != nil || writeFull(w, reply.data) != nil {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
	}
}

// Copy while the session lock still protects a download slot. Releasing the
// lock before copying would permit another lane's ACK to recycle that slot.
type laneReply struct {
	header http.Header
	status int
	data   []byte
}

func (w *laneReply) Header() http.Header { return w.header }
func (w *laneReply) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *laneReply) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	if len(p) > chunkSize-len(w.data) {
		return 0, errors.New("oversized lane reply")
	}
	w.data = append(w.data, p...)
	return len(p), nil
}
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type laneTransport struct {
	base    http.RoundTripper
	ctx     context.Context
	mu      sync.Mutex
	lanes   []*clientLane
	closed  bool
	builtin map[string]bool
}
type clientLane struct {
	endpoint   string
	busy       bool // protected by pool mutex
	writer     *io.PipeWriter
	cancel     context.CancelFunc
	ready      chan laneResponse
	reader     io.ReadCloser // only the exclusive exchange goroutine reads
	mu         sync.Mutex
	response   io.ReadCloser
	stopped    bool
	sendBuffer *bufio.Writer
}
type laneResponse struct {
	response *http.Response
	err      error
}

func (l *clientLane) stop() {
	l.cancel()
	l.writer.CloseWithError(io.ErrClosedPipe)
	l.mu.Lock()
	l.stopped = true
	r := l.response
	l.mu.Unlock()
	if r != nil {
		r.Close()
	}
}
func (t *laneTransport) close() {
	t.mu.Lock()
	t.closed = true
	lanes := append([]*clientLane(nil), t.lanes...)
	t.mu.Unlock()
	for _, l := range lanes {
		l.stop()
	}
}
func (t *laneTransport) acquire(r *http.Request) (*clientLane, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.ctx.Err() != nil {
		return nil, context.Canceled
	}
	endpoint := r.URL.String()
	for _, l := range t.lanes {
		if !l.busy && l.endpoint == endpoint {
			l.busy = true
			return l, nil
		}
	}
	// A single stream owns at most eight records per direction. Evict an idle
	// lane to another entry rather than multiplying pools by the node count.
	index := -1
	for i, l := range t.lanes {
		if len(t.lanes) >= 2*window && !l.busy {
			index = i
			break
		}
	}
	if index < 0 && len(t.lanes) >= 2*window {
		return nil, errors.New("lane pool capacity reached")
	}
	if index >= 0 {
		t.lanes[index].stop()
	}
	ctx, cancel := context.WithCancel(t.ctx)
	reader, writer := io.Pipe()
	req := r.Clone(ctx)
	req.Body = reader
	req.ContentLength = -1
	req.GetBody = nil
	req.Header.Set(LaneHeader, LaneVersion)
	l := &clientLane{endpoint: endpoint, busy: true, writer: writer, cancel: cancel, ready: make(chan laneResponse, 1)}
	if index >= 0 {
		t.lanes[index] = l
	} else {
		t.lanes = append(t.lanes, l)
	}
	go func() {
		resp, err := t.base.RoundTrip(req)
		if resp != nil {
			l.mu.Lock()
			l.response = resp.Body
			stopped := l.stopped
			l.mu.Unlock()
			if stopped {
				resp.Body.Close()
			}
		}
		l.ready <- laneResponse{resp, err}
		if err != nil {
			reader.CloseWithError(err)
		}
	}()
	return l, nil
}
func (t *laneTransport) release(l *clientLane, failed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if failed {
		l.stop()
		for i, p := range t.lanes {
			if p == l {
				t.lanes = append(t.lanes[:i], t.lanes[i+1:]...)
				break
			}
		}
	} else {
		l.busy = false
	}
}
func (t *laneTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.roundTripInto(r, nil)
}
func (t *laneTransport) roundTripInto(r *http.Request, buffer []byte) (*http.Response, error) {
	t.mu.Lock()
	builtin := t.builtin[r.URL.String()]
	t.mu.Unlock()
	if builtin {
		return t.base.RoundTrip(r)
	}
	// Session creation/close remain builtin operations, including tombstones.
	if r.ContentLength < headerSize {
		return nil, errors.New("invalid bond request")
	}
	l, err := t.acquire(r)
	if err != nil {
		return nil, err
	}
	done := make(chan laneResponse, 1)
	go func() { resp, err := l.exchange(r, buffer); done <- laneResponse{resp, err} }()
	var result laneResponse
	select {
	case result = <-done:
	case <-r.Context().Done():
		l.stop()
		result = <-done
		result.err = r.Context().Err()
	}
	t.release(l, result.err != nil || l.reader == nil)
	// A negotiated lane can be retired while idle although its hub session
	// is still live. This is a carrier failure, not an application pipe close:
	// retry the same idempotent record on a fresh lane/entry. Never convert a
	// failed initial TLS/auth negotiation or caller cancellation into a retry.
	if errors.Is(result.err, io.ErrClosedPipe) && l.reader != nil &&
		r.Context().Err() == nil && t.ctx.Err() == nil {
		result.err = errors.Join(io.ErrUnexpectedEOF, result.err)
	}
	if errors.Is(result.err, errLaneUnsupported) {
		// No operation record has been sent: only the session binding. A builtin
		// relay can omit the capability even when a different entry advertised it.
		t.mu.Lock()
		if t.builtin == nil {
			t.builtin = make(map[string]bool)
		}
		t.builtin[r.URL.String()] = true
		t.mu.Unlock()
		if r.GetBody == nil {
			return nil, errLaneUnsupported
		}
		body, err := r.GetBody()
		if err != nil {
			return nil, err
		}
		retry := r.Clone(r.Context())
		retry.Body = body
		return t.base.RoundTrip(retry)
	}
	return result.response, result.err
}
func (l *clientLane) exchange(r *http.Request, buffer []byte) (*http.Response, error) {
	if l.reader == nil {
		// Token is the first field after the operation in the builtin request body.
		var first [headerSize]byte
		if _, err := io.ReadFull(r.Body, first[:]); err != nil {
			return nil, err
		}
		if err := writeFull(l.writer, first[1:33]); err != nil {
			return nil, err
		}
		// Restore the header without retaining caller memory past this exchange.
		rbody := io.MultiReader(bytes.NewReader(first[:]), r.Body)
		ready := <-l.ready
		if ready.err != nil {
			return nil, ready.err
		}
		if ready.response.ProtoMajor != 2 && ready.response.ProtoMajor != 3 {
			return nil, errors.New("bond lane requires h2/h3")
		}
		if ready.response.StatusCode == 200 && ready.response.Header.Get(LaneHeader) != LaneVersion {
			return nil, errLaneUnsupported
		}
		if ready.response.StatusCode != 200 || ready.response.Header.Get(LaneHeader) != LaneVersion {
			// Preserve terminal authentication/hub statuses; never fall back on TLS errors.
			return &http.Response{StatusCode: ready.response.StatusCode, ProtoMajor: ready.response.ProtoMajor, Body: http.NoBody, ContentLength: 0}, nil
		}
		l.reader = ready.response.Body
		if err := l.send(rbody, r.ContentLength, r.Header.Get("X-Vetroff-Bond-Wait")); err != nil {
			return nil, err
		}
	} else if err := l.send(r.Body, r.ContentLength, r.Header.Get("X-Vetroff-Bond-Wait")); err != nil {
		return nil, err
	}
	var header [6]byte
	if _, err := io.ReadFull(l.reader, header[:]); err != nil {
		return nil, err
	}
	status := int(binary.BigEndian.Uint16(header[:2]))
	n := binary.BigEndian.Uint32(header[2:])
	if status < 200 || status > 599 || n > chunkSize {
		return nil, errors.New("invalid lane reply")
	}
	data := buffer
	if cap(data) < int(n) {
		data = make([]byte, int(n))
	} else {
		data = data[:int(n)]
	}
	if _, err := io.ReadFull(l.reader, data); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, ProtoMajor: 2, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(n)}, nil
}
func (l *clientLane) send(r io.Reader, n int64, waitHeader string) error {
	if n < headerSize || n > headerSize+chunkSize {
		return errors.New("invalid lane frame")
	}
	var size [8]byte
	binary.BigEndian.PutUint32(size[:4], uint32(n))
	wait, _ := time.ParseDuration(waitHeader)
	binary.BigEndian.PutUint32(size[4:], uint32(max(20*time.Millisecond, min(time.Second, wait))/time.Millisecond))
	if l.sendBuffer == nil {
		l.sendBuffer = bufio.NewWriterSize(l.writer, headerSize+chunkSize+8)
	}
	if err := writeFull(l.sendBuffer, size[:]); err != nil {
		return err
	}
	written, err := io.CopyN(l.sendBuffer, r, n)
	if err == nil && written != n {
		err = io.ErrUnexpectedEOF
	}
	if err == nil {
		err = l.sendBuffer.Flush()
	}
	return err
}
