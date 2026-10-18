package bond

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type pathState struct {
	pending int
	latency time.Duration
	retryAt time.Time
}
type Client struct {
	Endpoints          []*url.URL
	Transport          http.RoundTripper
	Username, Password string
	AttemptTimeout     time.Duration
	SetupTimeout       time.Duration
	// Pipeline is 0 (automatic), 4, or 8. Configure before Open.
	Pipeline int
	// Weights are relative configured capacities (1..100), not traffic quotas.
	// ExpectedHub optionally pins the exit before the first destination dial.
	Weights     []int
	ExpectedHub string
	mu          sync.Mutex
	paths       []pathState
	next        uint64
}

func (c *Client) reserve(tried []bool) (int, func(time.Duration, bool)) {
	c.mu.Lock()
	if len(c.paths) != len(c.Endpoints) {
		c.paths = make([]pathState, len(c.Endpoints))
		// Independent clients must not all probe the first configured node first.
		var seed [8]byte
		if _, err := rand.Read(seed[:]); err == nil {
			c.next = binary.BigEndian.Uint64(seed[:])
		}
	}
	now := time.Now()
	selected := -1
	best := time.Duration(1<<63 - 1)
	start := int(c.next % uint64(len(tried)))
	c.next++
	for i := range tried {
		index := (start + i) % len(tried)
		if tried[index] {
			continue
		}
		p := c.paths[index]
		delay := p.latency
		if delay == 0 {
			delay = 100 * time.Millisecond
		}
		score := delay * time.Duration(p.pending+1)
		if len(c.Weights) == len(c.Endpoints) && c.Weights[index] > 0 {
			score /= time.Duration(c.Weights[index])
		}
		if p.latency == 0 && p.pending == 0 {
			score = 0
		}
		if now.Before(p.retryAt) {
			score += time.Hour
		}
		if selected < 0 || score < best {
			selected = index
			best = score
		}
	}
	c.paths[selected].pending++
	c.mu.Unlock()
	return selected, func(elapsed time.Duration, failed bool) {
		c.mu.Lock()
		defer c.mu.Unlock()
		p := &c.paths[selected]
		p.pending--
		if failed {
			p.retryAt = time.Now().Add(5 * time.Second)
			return
		}
		p.retryAt = time.Time{}
		if elapsed <= 0 {
			return
		}
		if p.latency == 0 {
			p.latency = elapsed
		} else {
			p.latency = (7*p.latency + elapsed) / 8
		}
	}
}
func terminal(err error) bool {
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	var invalid x509.CertificateInvalidError
	var roots x509.SystemRootsError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	var operation *net.OpError
	return errors.As(err, &roots) || errors.As(err, &record) || errors.As(err, &alert) || (errors.As(err, &operation) && operation.Op == "remote error") || errors.As(err, &cert) || errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid)
}
func (c *Client) request(ctx context.Context, token []byte, hub string, op byte, seq, ack uint64, payload []byte) (block, error) {
	return c.requestInto(ctx, token, hub, op, seq, ack, payload, nil)
}
func (c *Client) requestInto(ctx context.Context, token []byte, hub string, op byte, seq, ack uint64, payload, responseBuffer []byte) (block, error) {
	frame := make([]byte, headerSize)
	frame[0] = op
	copy(frame[1:33], token)
	binary.BigEndian.PutUint64(frame[33:41], seq)
	binary.BigEndian.PutUint64(frame[41:49], ack)
	tried := make([]bool, len(c.Endpoints))
	var last error
	for range tried {
		if ctx.Err() != nil {
			return block{}, ctx.Err()
		}
		index, release := c.reserve(tried)
		tried[index] = true
		timeout := c.attemptBudget(index, op)
		attempt, cancel := context.WithTimeout(ctx, timeout)
		endpoint := *c.Endpoints[index]
		endpoint.Path = Path
		frames := &frameSet{header: frame, payload: payload}
		body, _ := frames.body()
		req, err := http.NewRequestWithContext(attempt, http.MethodPost, endpoint.String(), body)
		if err != nil {
			cancel()
			frames.close()
			release(0, true)
			return block{}, err
		}
		req.ContentLength = int64(headerSize + len(payload))
		req.GetBody = frames.body
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
		req.Header.Set("Content-Type", "application/octet-stream")
		if hub != "" {
			req.Header.Set("X-FoxTunnel-Bond-Hub", hub)
		}
		req.Header.Set("X-FoxTunnel-Bond-Wait", min(timeout/3, time.Second).String())
		started := time.Now()
		resp, err := c.Transport.RoundTrip(req)
		var data []byte
		status := 0
		if err == nil {
			status = resp.StatusCode
			if resp.ProtoMajor != 2 {
				err = errors.New(i18n.Text("bond requires HTTP/2"))
			} else {
				data, err = readBoundedInto(resp.Body, resp.ContentLength, chunkSize, responseBuffer)
				if len(data) > chunkSize {
					err = errors.New(i18n.Text("oversized bond response"))
				}
			}
			resp.Body.Close()
		}
		if err == nil && op == opRead && status == 200 && len(data) == 0 {
			err = io.ErrUnexpectedEOF
		}
		elapsed := time.Since(started)
		cancel()
		frames.close() // Join any in-progress Read before an upload slot can be reused.
		retry := false
		if err != nil {
			var network net.Error
			retry = !terminal(err) && (errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded))
		} else {
			retry = status == 429 || status == 408 || status == 503 || status == 504
		}
		measured := elapsed
		if op == opRead && status != http.StatusOK {
			measured = 0
		} // Long polls do not estimate path delay.
		release(measured, err != nil || retry)
		if err == nil && !retry {
			switch status {
			case 200:
				return block{data: data}, nil
			case 201:
				return block{eof: true}, nil
			case 204:
				return block{}, errPoll
			default:
				return block{}, fmt.Errorf(i18n.Text("bond HTTP status %d"), status)
			}
		}
		if !retry {
			return block{}, err
		}
		last = err
		if last == nil {
			last = fmt.Errorf(i18n.Text("bond HTTP status %d"), status)
		}
	}
	return block{}, last
}

var errPoll = errors.New("poll again")

type result struct {
	block
	err    error
	buffer []byte
}
type Stream struct {
	client                      *Client
	token                       [32]byte
	hub                         string
	ctx                         context.Context
	cancel                      context.CancelFunc
	once                        sync.Once
	writeMu, readMu             sync.Mutex
	nextUp, nextRead, nextFetch uint64
	writeClosed                 bool
	uploadSlots                 chan *[chunkSize]byte
	uploadPending               sync.WaitGroup
	readEOF                     bool
	readCtx                     context.Context
	readCancel                  context.CancelFunc
	current                     []byte
	futures                     map[uint64]chan result
	receivePool                 [][]byte
	currentBuffer               []byte
	uploadCapacity              int
	workers                     sync.WaitGroup
	ackMu                       sync.Mutex
	ack                         uint64
}

func (c *Client) Open(ctx context.Context, target string) (*Stream, error) {
	if c.Pipeline != 0 && c.Pipeline != 4 && c.Pipeline != window {
		return nil, errors.New(i18n.Text("bond pipeline must be auto, 4 or 8"))
	}
	if len(c.Endpoints) < 1 || len(c.Endpoints) > 8 || (len(c.Endpoints) == 1 && c.ExpectedHub == "") || c.Transport == nil {
		return nil, errors.New(i18n.Text("bond requires two to eight trusted nodes"))
	}
	if c.ExpectedHub != "" {
		id, err := hex.DecodeString(c.ExpectedHub)
		if err != nil || len(id) != 32 || hex.EncodeToString(id) != c.ExpectedHub {
			return nil, errors.New(i18n.Text("invalid bond hub identity"))
		}
	}
	if len(c.Weights) != 0 {
		if len(c.Weights) != len(c.Endpoints) {
			return nil, errors.New(i18n.Text("invalid cluster configuration"))
		}
		for _, weight := range c.Weights {
			if weight < 1 || weight > 100 {
				return nil, errors.New(i18n.Text("invalid cluster configuration"))
			}
		}
	}
	streamCtx, cancel := context.WithCancel(ctx)
	s := &Stream{client: c, ctx: streamCtx, cancel: cancel, futures: make(map[uint64]chan result), uploadSlots: make(chan *[chunkSize]byte, window)}
	s.uploadCapacity = c.pipelineDepth()
	for range s.uploadCapacity {
		s.uploadSlots <- nil
	}
	s.readCtx, s.readCancel = context.WithCancel(streamCtx)
	binary.BigEndian.PutUint64(s.token[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(s.token[8:]); err != nil {
		cancel()
		return nil, err
	}
	setupTimeout := c.SetupTimeout
	if setupTimeout <= 0 {
		setupTimeout = 15 * time.Second
	}
	setup, stop := context.WithTimeout(streamCtx, setupTimeout)
	defer stop()
	opened, err := c.request(setup, s.token[:], c.ExpectedHub, opOpen, 0, 0, []byte(target))
	if err != nil {
		cancel()
		return nil, err
	}
	if len(opened.data) != 32 {
		cancel()
		return nil, errors.New(i18n.Text("invalid bond hub identity"))
	}
	s.hub = hex.EncodeToString(opened.data)
	if c.ExpectedHub != "" && s.hub != c.ExpectedHub {
		cancel()
		return nil, errors.New(i18n.Text("invalid bond hub identity"))
	}
	return s, nil
}
func (s *Stream) fetch() {
	seq := s.nextFetch
	s.nextFetch++
	out := make(chan result, 1)
	s.futures[seq] = out
	var responseBuffer []byte
	if n := len(s.receivePool); n > 0 {
		responseBuffer = s.receivePool[n-1]
		s.receivePool = s.receivePool[:n-1]
	} else {
		responseBuffer = make([]byte, chunkSize+1)
	}
	s.workers.Go(func() {
		for {
			s.ackMu.Lock()
			ack := s.ack
			s.ackMu.Unlock()
			b, err := s.client.requestInto(s.readCtx, s.token[:], s.hub, opRead, seq, ack, nil, responseBuffer)
			if errors.Is(err, errPoll) {
				continue
			}
			out <- result{block: b, err: err, buffer: responseBuffer}
			return
		}
	})
}
func (s *Stream) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if s.readEOF {
		return 0, io.EOF
	}
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	if len(s.current) == 0 {
		for s.nextFetch < s.nextRead+uint64(s.client.pipelineDepth()) {
			s.fetch()
		}
		select {
		case r := <-s.futures[s.nextRead]:
			if r.err != nil {
				s.receivePool = append(s.receivePool, r.buffer)
				s.cancel()
				return 0, r.err
			}
			if r.eof {
				s.receivePool = append(s.receivePool, r.buffer)
				s.readEOF = true
				s.readCancel()
				return 0, io.EOF
			}
			s.current = r.data
			s.currentBuffer = r.buffer
		case <-s.ctx.Done():
			return 0, s.ctx.Err()
		}
	}
	n := copy(p, s.current)
	s.current = s.current[n:]
	if len(s.current) == 0 {
		s.receivePool = append(s.receivePool, s.currentBuffer)
		s.currentBuffer = nil
		delete(s.futures, s.nextRead)
		s.nextRead++
		s.ackMu.Lock()
		s.ack = s.nextRead
		s.ackMu.Unlock()
	}
	return n, nil
}

// Write buffers at most four upload blocks. Workers can use independent nodes
// concurrently even when SOCKS/TCP supplies one small read at a time.
func (s *Stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return 0, io.ErrClosedPipe
	}
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	written := 0
	for len(p) > 0 {
		// Capacity grows monotonically for this stream; there is no revocation of
		// slots already owned by workers and no change to the server wire window.
		for desired := s.client.pipelineDepth(); s.uploadCapacity < desired; s.uploadCapacity++ {
			s.uploadSlots <- nil
		}
		var buffer *[chunkSize]byte
		select {
		case buffer = <-s.uploadSlots:
		case <-s.ctx.Done():
			return written, s.ctx.Err()
		}
		n := min(len(p), chunkSize)
		if buffer == nil {
			buffer = new([chunkSize]byte)
		}
		payload := buffer[:n]
		copy(payload, p[:n])
		p = p[n:]
		seq := s.nextUp
		s.nextUp++
		written += n
		s.uploadPending.Add(1)
		s.workers.Go(func() {
			defer s.uploadPending.Done()
			defer func() { s.uploadSlots <- buffer }()
			for {
				_, err := s.client.request(s.ctx, s.token[:], s.hub, opWrite, seq, 0, payload)
				if errors.Is(err, errPoll) {
					continue
				}
				if err != nil {
					s.cancel()
				}
				return
			}
		})
	}
	return written, nil
}
func (s *Stream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed {
		return nil
	}
	s.writeClosed = true
	s.uploadPending.Wait()
	if err := s.ctx.Err(); err != nil {
		return err
	}
	for {
		_, err := s.client.request(s.ctx, s.token[:], s.hub, opFin, s.nextUp, 0, nil)
		if !errors.Is(err, errPoll) {
			return err
		}
	}
}
func (s *Stream) Close() error {
	s.once.Do(func() {
		s.cancel()
		// Serialize with Read/Write before waiting: no worker can be added after Wait.
		s.readMu.Lock()
		s.writeMu.Lock()
		s.workers.Wait()
		s.writeMu.Unlock()
		s.readMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = s.client.request(ctx, s.token[:], s.hub, opClose, 0, 0, nil)
	})
	return nil
}

// pipelineDepth uses observed full-exchange duration, not a pure RTT estimate.
// Ignore cooling/unknown paths and prefer the fastest measured usable path.
// Four slots stay the low-latency default; high delay can use the existing
// eight-record wire window. This is bounded tuning, not a bandwidth estimator.
func (c *Client) pipelineDepth() int {
	if c.Pipeline == 4 || c.Pipeline == window {
		return c.Pipeline
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	fastest := time.Duration(0)
	for _, p := range c.paths {
		if p.latency <= 0 || now.Before(p.retryAt) {
			continue
		}
		if fastest == 0 || p.latency < fastest {
			fastest = p.latency
		}
	}
	if fastest >= 25*time.Millisecond {
		return window
	}
	return 4
}

// A measured usable alternative permits a bounded earlier retry of session-
// scoped operations. Open keeps the full setup budget; idle poll wait is chosen
// below this attempt budget. Unknown/cooling alternatives cannot shorten it.
func (c *Client) attemptBudget(selected int, op byte) time.Duration {
	budget := c.AttemptTimeout
	if budget <= 0 {
		budget = 3 * time.Second
	}
	if op == opOpen {
		return budget
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	fastest := time.Duration(0)
	for i, p := range c.paths {
		if i == selected || p.latency <= 0 || now.Before(p.retryAt) {
			continue
		}
		if fastest == 0 || p.latency < fastest {
			fastest = p.latency
		}
	}
	if fastest > 0 {
		budget = min(budget, max(250*time.Millisecond, 4*fastest))
	}
	return budget
}
