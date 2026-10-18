package bond

import (
	"bytes"
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
	mu                 sync.Mutex
	paths              []pathState
	next               uint64
}

func (c *Client) reserve(tried []bool) (int, func(time.Duration, bool)) {
	c.mu.Lock()
	if len(c.paths) != len(c.Endpoints) {
		c.paths = make([]pathState, len(c.Endpoints))
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
	frame := make([]byte, headerSize+len(payload))
	frame[0] = op
	copy(frame[1:33], token)
	binary.BigEndian.PutUint64(frame[33:41], seq)
	binary.BigEndian.PutUint64(frame[41:49], ack)
	copy(frame[49:], payload)
	tried := make([]bool, len(c.Endpoints))
	var last error
	for range tried {
		if ctx.Err() != nil {
			return block{}, ctx.Err()
		}
		index, release := c.reserve(tried)
		tried[index] = true
		timeout := c.AttemptTimeout
		if timeout <= 0 {
			timeout = 3 * time.Second
		}
		attempt, cancel := context.WithTimeout(ctx, timeout)
		endpoint := *c.Endpoints[index]
		endpoint.Path = Path
		req, err := http.NewRequestWithContext(attempt, http.MethodPost, endpoint.String(), bytes.NewReader(frame))
		if err != nil {
			cancel()
			release(0, true)
			return block{}, err
		}
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
				data, err = readBounded(resp.Body, resp.ContentLength, chunkSize)
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
		retry := false
		if err != nil {
			var network net.Error
			retry = !terminal(err) && (errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded))
		} else {
			retry = status == 429 || status == 408 || status == 503 || status == 504
		}
		release(elapsed, err != nil || retry)
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
	err error
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
	uploadSlots                 chan struct{}
	uploadPending               sync.WaitGroup
	readEOF                     bool
	readCtx                     context.Context
	readCancel                  context.CancelFunc
	current                     []byte
	futures                     map[uint64]chan result
	workers                     sync.WaitGroup
	ackMu                       sync.Mutex
	ack                         uint64
}

func (c *Client) Open(ctx context.Context, target string) (*Stream, error) {
	if len(c.Endpoints) < 2 || len(c.Endpoints) > 8 || c.Transport == nil {
		return nil, errors.New(i18n.Text("bond requires two to eight trusted nodes"))
	}
	streamCtx, cancel := context.WithCancel(ctx)
	s := &Stream{client: c, ctx: streamCtx, cancel: cancel, futures: make(map[uint64]chan result), uploadSlots: make(chan struct{}, 4)}
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
	opened, err := c.request(setup, s.token[:], "", opOpen, 0, 0, []byte(target))
	if err != nil {
		cancel()
		return nil, err
	}
	if len(opened.data) != 32 {
		cancel()
		return nil, errors.New(i18n.Text("invalid bond hub identity"))
	}
	s.hub = hex.EncodeToString(opened.data)
	return s, nil
}
func (s *Stream) fetch() {
	seq := s.nextFetch
	s.nextFetch++
	out := make(chan result, 1)
	s.futures[seq] = out
	s.workers.Go(func() {
		for {
			s.ackMu.Lock()
			ack := s.ack
			s.ackMu.Unlock()
			b, err := s.client.request(s.readCtx, s.token[:], s.hub, opRead, seq, ack, nil)
			if errors.Is(err, errPoll) {
				continue
			}
			out <- result{b, err}
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
	if len(s.current) == 0 {
		for s.nextFetch < s.nextRead+4 {
			s.fetch()
		}
		select {
		case r := <-s.futures[s.nextRead]:
			if r.err != nil {
				s.cancel()
				return 0, r.err
			}
			if r.eof {
				s.readEOF = true
				s.readCancel()
				return 0, io.EOF
			}
			s.current = r.data
		case <-s.ctx.Done():
			return 0, s.ctx.Err()
		}
	}
	n := copy(p, s.current)
	s.current = s.current[n:]
	if len(s.current) == 0 {
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
	written := 0
	for len(p) > 0 {
		select {
		case s.uploadSlots <- struct{}{}:
		case <-s.ctx.Done():
			return written, s.ctx.Err()
		}
		n := min(len(p), chunkSize)
		payload := append([]byte(nil), p[:n]...)
		p = p[n:]
		seq := s.nextUp
		s.nextUp++
		written += n
		s.uploadPending.Add(1)
		s.workers.Go(func() {
			defer s.uploadPending.Done()
			defer func() { <-s.uploadSlots }()
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
