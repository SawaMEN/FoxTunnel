package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/SawaMEN/FoxTunnel/internal/cluster"
	"github.com/SawaMEN/FoxTunnel/internal/i18n"
	"github.com/SawaMEN/FoxTunnel/internal/nodeperf"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const maxProxyEndpoints = 8

var errH2Required = i18n.Error(i18n.Text("proxy must negotiate h2 ALPN"))

func parseServerURL(raw string) (*url.URL, error) {
	u, err := cluster.Origin(raw)
	if err != nil {
		return nil, errors.New(i18n.Text("server must be an https://host[:port] URL"))
	}
	return u, nil
}

// SetFallbackServers configures explicitly trusted proxy origins before Serve.
// Every origin receives the configured proxy credentials, but only after TLS
// verification. No discovery, redirects, cleartext fallback or protocol change.
func (c *Client) SetFallbackServers(rawURLs []string) error {
	if pool, ok := c.transport.(*identityPool); ok && len(pool.nodePolicies) != 0 {
		return errors.New("configure fallback servers before per-node SPKI pins")
	}
	if len(rawURLs) >= maxProxyEndpoints {
		return fmt.Errorf(i18n.Text("at most %d fallback servers are allowed"), maxProxyEndpoints-1)
	}
	key := cluster.OriginKey
	seen := map[string]bool{key(c.ServerURL): true}
	endpoints := make([]*url.URL, 0, len(rawURLs))
	for _, raw := range rawURLs {
		u, err := parseServerURL(raw)
		if err != nil {
			return err
		}
		if seen[key(u)] {
			return errors.New(i18n.Text("duplicate proxy origin"))
		}
		seen[key(u)] = true
		endpoints = append(endpoints, u)
	}
	c.fallbackServers = endpoints
	c.preferredEndpoint.Store(0)
	c.schedulerMu.Lock()
	c.adaptiveState = nodeperf.SelectionState{}
	c.schedulerMu.Unlock()
	return nil
}

type openStream struct {
	response *http.Response
	reader   *io.PipeReader
	writer   *io.PipeWriter
	cancel   context.CancelFunc
	release  func()
	once     sync.Once
}

func (s *openStream) close() {
	s.once.Do(func() { s.cancel(); s.response.Body.Close(); s.reader.Close(); s.writer.Close(); s.release() })
}

// openTunnel performs only CONNECT setup. Application bytes are never written
// here, so a failed setup can move to another explicitly configured origin.
// An HTTP response or verification/protocol failure is always terminal.
func (c *Client) openTunnel(ctx context.Context, target string) (*openStream, error) {
	endpoints := append([]*url.URL{c.ServerURL}, c.fallbackServers...)
	tried := make([]bool, len(endpoints))
	timeout := c.ConnectTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var last error
	for offset := 0; offset < len(endpoints); offset++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		budget := time.Until(deadline)
		if budget <= 0 {
			return nil, context.DeadlineExceeded
		}
		if len(endpoints) > 1 {
			attempt := c.FallbackAttemptTimeout
			if attempt <= 0 {
				attempt = 5 * time.Second
			}
			budget = min(budget, attempt)
		}
		index, release := c.reserveEndpoint(tried)
		tried[index] = true
		attemptCtx, abort := context.WithCancelCause(ctx)
		cancel := func() { abort(context.Canceled) }
		reader, writer := io.Pipe()
		req, err := http.NewRequestWithContext(attemptCtx, http.MethodConnect, endpoints[index].String(), reader)
		if err != nil {
			reader.Close()
			writer.Close()
			cancel()
			release()
			return nil, err
		}
		req.Host = target
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password)))
		if c.Padding {
			req.Header.Set(paddingHeader, paddingVersion)
		}
		c.requestProtocol(req, "tcp")
		timer := time.AfterFunc(budget, func() { abort(context.DeadlineExceeded) })
		resp, err := c.transport.RoundTrip(req)
		timedOut := !timer.Stop()
		if err == nil && !timedOut && attemptCtx.Err() == nil {
			if (resp.ProtoMajor != 2 && resp.ProtoMajor != 3) || resp.StatusCode != http.StatusOK {
				err = fmt.Errorf(i18n.Text("CONNECT rejected (HTTP/%d status %d)"), resp.ProtoMajor, resp.StatusCode)
			} else if protocolErr := c.verifyProtocol(resp, "tcp"); protocolErr != nil {
				err = protocolErr
			} else {
				negotiated, paddingErr := paddingRequested(resp.Header)
				if paddingErr != nil || negotiated != c.Padding {
					err = errors.New(i18n.Text("CONNECT padding negotiation failed"))
				}
			}
			if err == nil {
				if c.balance != "adaptive" {
					c.preferredEndpoint.Store(uint32(index))
				}
				c.endpointResult(index, false)
				return &openStream{response: resp, reader: reader, writer: writer, cancel: cancel, release: release}, nil
			}
		}
		// Any response proves the peer answered. Do not reinterpret HTTP errors,
		// negotiation failures or a response/deadline race as a network outage.
		answered := resp != nil
		// Unblock both upload and context-dependent response teardown first.
		// Some duplex transports join their writer from Body.Close.
		cancel()
		reader.Close()
		writer.Close()
		if resp != nil {
			resp.Body.Close()
		}
		release()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if terminalSetupError(err) {
			return nil, err
		}
		if timedOut && !answered {
			if err != nil && !errors.Is(err, context.Canceled) && !retryableSetupError(err) {
				return nil, err
			}
			err = context.DeadlineExceeded
		}
		if err == nil {
			err = context.Canceled
		}
		if answered || (!timedOut && !retryableSetupError(err)) {
			return nil, err
		}
		c.endpointResult(index, true)
		last = err
	}
	return nil, last
}
func certificateFailure(err error) bool {
	var verification *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var roots x509.SystemRootsError
	return errors.As(err, &verification) || errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &roots)
}
func terminalSetupError(err error) bool {
	if certificateFailure(err) || errors.Is(err, errH2Required) || errors.Is(err, errWSHandshake) {
		return true
	}
	var record tls.RecordHeaderError
	var alert tls.AlertError
	var operation *net.OpError
	if errors.As(err, &record) || errors.As(err, &alert) {
		return true
	}
	return errors.As(err, &operation) && operation.Op == "remote error"
}
func retryableSetupError(err error) bool {
	if terminalSetupError(err) {
		return false
	}
	var networkError net.Error
	return errors.As(err, &networkError) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed)
}

// The default net/http transport can otherwise fall back to HTTP/1.1. Require
// h2 before sending any proxy authorization, matching the NSS backend policy.
func dialGoH2(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	cfg := config.Clone()
	cfg.NextProtos = []string{"h2"}
	if cfg.ServerName == "" {
		cfg.ServerName, _, err = net.SplitHostPort(addr)
		if err != nil {
			raw.Close()
			return nil, err
		}
	}
	secure := tls.Client(raw, cfg)
	handshake, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := secure.HandshakeContext(handshake); err != nil {
		raw.Close()
		return nil, err
	}
	if secure.ConnectionState().NegotiatedProtocol != "h2" {
		raw.Close()
		return nil, errH2Required
	}
	return secure, nil
}

// SetBalance configures new-stream scheduling before Serve. A stream is never
// striped or replayed; counts include both setup and established streams.
func (c *Client) SetBalance(mode string) error {
	if mode == "adaptive" && (c.bondClient != nil || c.bondDiscovery != nil) {
		return errors.New("adaptive balance cannot be combined with bond")
	}
	switch mode {
	case "failover", "round-robin", "least-active", "adaptive":
	default:
		return fmt.Errorf(i18n.Text("unknown balance mode %q"), mode)
	}
	c.schedulerMu.Lock()
	c.balance = mode
	c.adaptiveState = nodeperf.SelectionState{}
	c.schedulerMu.Unlock()
	return nil
}
func (c *Client) reserveEndpoint(tried []bool) (int, func()) {
	c.schedulerMu.Lock()
	if c.balance == "adaptive" && c.nodeMetrics != nil {
		endpoints := append([]*url.URL{c.ServerURL}, c.fallbackServers...)
		candidates := make([]nodeperf.Candidate, len(tried))
		for i := range tried {
			candidates[i] = nodeperf.Candidate{
				Origin:  endpoints[i].Scheme + "://" + endpoints[i].Host,
				Active:  c.activeEndpoints[i],
				RetryAt: c.endpointRetryAt[i],
				Tried:   tried[i],
			}
		}
		selected, next := nodeperf.Select(candidates, c.nodeMetrics.Snapshot(), c.adaptiveState, time.Now())
		c.adaptiveState = next
		if selected < 0 {
			c.schedulerMu.Unlock()
			return -1, func() {}
		}
		c.activeEndpoints[selected]++
		c.schedulerMu.Unlock()
		var once sync.Once
		return selected, func() {
			once.Do(func() {
				c.schedulerMu.Lock()
				c.activeEndpoints[selected]--
				c.schedulerMu.Unlock()
			})
		}
	}
	start := int(c.preferredEndpoint.Load() % uint32(len(tried)))
	if c.balance == "round-robin" || c.balance == "least-active" {
		start = int(c.nextEndpoint % uint64(len(tried)))
		c.nextEndpoint++
	}
	selected := -1
	now := time.Now()
	for offset := range tried {
		index := (start + offset) % len(tried)
		if tried[index] {
			continue
		}
		ready := !now.Before(c.endpointRetryAt[index])
		selectedReady := selected >= 0 && !now.Before(c.endpointRetryAt[selected])
		if selected < 0 || (ready && !selectedReady) || (ready == selectedReady && c.balance == "least-active" && c.activeEndpoints[index] < c.activeEndpoints[selected]) {
			selected = index
		}
	}
	c.activeEndpoints[selected]++
	c.schedulerMu.Unlock()
	var once sync.Once
	return selected, func() {
		once.Do(func() { c.schedulerMu.Lock(); c.activeEndpoints[selected]--; c.schedulerMu.Unlock() })
	}
}

// Only transient setup failures enter cooldown. If every endpoint is cooling,
// try immediately rather than waiting or locking the user out of recovery.
func (c *Client) endpointResult(index int, failed bool) {
	c.schedulerMu.Lock()
	defer c.schedulerMu.Unlock()
	if !failed {
		c.endpointFailures[index] = 0
		c.endpointRetryAt[index] = time.Time{}
		return
	}
	if c.endpointFailures[index] < 6 {
		c.endpointFailures[index]++
	}
	delay := min(time.Second<<(c.endpointFailures[index]-1), 30*time.Second)
	c.endpointRetryAt[index] = time.Now().Add(delay)
}
