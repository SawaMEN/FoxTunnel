//go:build neqo && cgo && linux && amd64

package neqo

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/tlsidentity"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func testServer(t *testing.T, handler http.Handler) (string, *tls.Config) {
	return testServerQUIC(t, handler, nil)
}
func testServerQUIC(t *testing.T, handler http.Handler, config *quic.Config) (string, *tls.Config) {
	t.Helper()
	tcp := httptest.NewUnstartedServer(handler)
	tcp.EnableHTTP2 = true
	tcp.StartTLS()
	t.Cleanup(tcp.Close)
	addr := strings.TrimPrefix(tcp.URL, "https://")
	socket, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: tcp.TLS.Certificates, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, QUICConfig: config}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(socket) }()
	t.Cleanup(func() { server.Close(); socket.Close(); <-done })
	roots := x509.NewCertPool()
	roots.AddCert(tcp.Certificate())
	return tcp.URL, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
}

type flushing struct{ http.ResponseWriter }

func (w flushing) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err == nil {
		err = http.NewResponseController(w.ResponseWriter).Flush()
	}
	return n, err
}
func TestIndependentH3EchoReuseAndColdHandshake(t *testing.T) {
	var mu sync.Mutex
	peers := make(map[string]bool)
	var calls atomic.Int64
	raw, cfg := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 || r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.Header.Get("Proxy-Authorization") != "Basic test-only" {
			t.Error("incorrect verified H3 request")
		}
		calls.Add(1)
		mu.Lock()
		peers[r.RemoteAddr] = true
		mu.Unlock()
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		_, _ = io.Copy(flushing{w}, r.Body)
	}))
	client, err := NewTransport(Config{TLS: cfg, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for round := range 3 {
		if round == 2 {
			client.CloseIdleConnections()
		}
		payload := make([]byte, 512<<10)
		for i := range payload {
			payload[i] = byte((i*19 + i/32768) % 251)
		}
		req, _ := http.NewRequest("POST", raw+"/echo", bytes.NewReader(payload))
		req.Header.Set("Proxy-Authorization", "Basic test-only")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req = req.WithContext(ctx)
		resp, err := client.RoundTrip(req)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		cancel()
		if err != nil || !bytes.Equal(got, payload) || resp.ProtoMajor != 3 || resp.TLS == nil || resp.TLS.CipherSuite == 0 || !resp.TLS.HandshakeComplete {
			t.Fatalf("echo %d: length=%d %v", round, len(got), err)
		}
	}
	mu.Lock()
	count := len(peers)
	mu.Unlock()
	if count != 2 || calls.Load() != 3 {
		t.Fatal("connection reuse/cold handshake", count, calls.Load())
	}
}
func TestTrustBeforeCredentials(t *testing.T) {
	var received atomic.Int64
	raw, cfg := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1); w.WriteHeader(200) }))
	for _, name := range []string{"CA", "SNI", "pin"} {
		t.Run(name, func(t *testing.T) {
			config := cfg.Clone()
			switch name {
			case "CA":
				config.RootCAs = x509.NewCertPool()
			case "SNI":
				config.ServerName = "wrong.example"
			case "pin":
				policy, _ := tlsidentity.Normalize("", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
				policy.Apply(config)
			}
			client, err := NewTransport(Config{TLS: config, HandshakeTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			req, _ := http.NewRequest("GET", raw, nil)
			req.Header.Set("Proxy-Authorization", "must-not-be-sent")
			_, err = client.RoundTrip(req)
			if err == nil {
				t.Fatal("bad trust accepted")
			}
			var unreachable *ReachabilityError
			if errors.As(err, &unreachable) {
				t.Fatal("trust failure classified as network fallback")
			}
			if received.Load() != 0 {
				t.Fatal("credentials preceded trust verification")
			}
		})
	}
}
func TestConcurrentDuplexAndCancellation(t *testing.T) {
	blocked := make(chan struct{}, 1)
	raw, cfg := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		if r.URL.Path == "/wait" {
			blocked <- struct{}{}
			<-r.Context().Done()
			return
		}
		_, _ = io.Copy(flushing{w}, r.Body)
	}))
	client, err := NewTransport(Config{TLS: cfg, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	var wg sync.WaitGroup
	for seed := range 4 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			reader, writer := io.Pipe()
			payload := bytes.Repeat([]byte{byte(seed), 17, 31}, 64<<10)
			req, _ := http.NewRequestWithContext(ctx, "POST", raw+"/echo", reader)
			done := make(chan error, 1)
			go func() { _, err := writer.Write(payload); writer.CloseWithError(err); done <- err }()
			resp, err := client.RoundTrip(req)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || !bytes.Equal(payload, got) {
				t.Error("concurrent echo", len(got), err)
			}
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", raw+"/wait", nil)
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	<-blocked
	done := make(chan error, 1)
	go func() { _, err := resp.Body.Read(make([]byte, 32)); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled read retained its borrowed buffer")
	}
	resp.Body.Close()
	req, _ = http.NewRequest("GET", raw+"/echo", nil)
	resp, err = client.RoundTrip(req)
	if err != nil {
		t.Fatal("cancel poisoned shared connection", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
func TestBlockedUDPBoundedProbe(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	// Keep the port open and deliberately discard every Initial, avoiding a
	// fast ICMP refusal so the configured timeout is actually exercised.
	go func() {
		p := make([]byte, 2048)
		for {
			if _, _, err := udp.ReadFrom(p); err != nil {
				return
			}
		}
	}()
	client, err := NewTransport(Config{TLS: &tls.Config{}, HandshakeTimeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	u, _ := url.Parse("https://" + udp.LocalAddr().String())
	started := time.Now()
	err = client.Probe(context.Background(), u)
	var unreachable *ReachabilityError
	if !errors.As(err, &unreachable) || time.Since(started) > time.Second {
		t.Fatal("blocked UDP budget", err, time.Since(started))
	}
}

func TestALPNFailureIsTerminal(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: fixture.TLS.Certificates, NextProtos: []string{"not-h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	client, err := NewTransport(Config{TLS: &tls.Config{RootCAs: roots}, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	u, _ := url.Parse("https://" + listener.Addr().String())
	err = client.Probe(context.Background(), u)
	var unreachable *ReachabilityError
	if err == nil || errors.As(err, &unreachable) {
		t.Fatal("ALPN failure allowed network downgrade", err)
	}
}

type closeNotice struct {
	io.ReadCloser
	once     sync.Once
	closed   chan struct{}
	readOnce sync.Once
	reading  chan struct{}
}

func (b *closeNotice) Read(p []byte) (int, error) {
	b.readOnce.Do(func() { close(b.reading) })
	return b.ReadCloser.Read(p)
}
func (b *closeNotice) Close() error {
	b.once.Do(func() { b.ReadCloser.Close(); close(b.closed) })
	return nil
}
func TestPeerResetClosesIdleUpload(t *testing.T) {
	reset := make(chan struct{})
	raw, cfg := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		<-reset
		panic(http.ErrAbortHandler)
	}))
	client, err := NewTransport(Config{TLS: cfg, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	reader, writer := io.Pipe()
	defer writer.Close()
	body := &closeNotice{ReadCloser: reader, closed: make(chan struct{}), reading: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", raw, body)
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-body.reading
	close(reset)
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("peer reset retained a blocked request-body reader")
	}
	_, err = resp.Body.Read(make([]byte, 1))
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatal("peer reset was hidden as successful EOF", err)
	}
}
func TestMalformedResponseDoesNotWaitForContext(t *testing.T) {
	raw, cfg := testServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Content-Length"] = []string{"3", "4"}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("abc"))
	}))
	client, err := NewTransport(Config{TLS: cfg, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
	resp, err := client.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || ctx.Err() != nil {
		t.Fatal("malformed headers succeeded or hung until context expired", err)
	}
}

func TestFinalH3ReadDeliversBytesBeforeEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	owner := &transport{}
	c := &connection{owner: owner, ctx: ctx, commands: make(chan command),
		done: make(chan struct{}), active: 1}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.org/", nil)
	s := &stream{conn: c, req: req, closed: make(chan struct{}),
		uploadDone: make(chan struct{})}
	close(s.uploadDone)
	done := make(chan struct{})
	go func() {
		defer close(done)
		readCount := 0
		for {
			select {
			case cmd := <-c.commands:
				switch cmd.kind {
				case 'r':
					readCount++
					if readCount == 1 {
						copy(cmd.data, "last")
						cmd.reply <- result{n: 4, fin: true}
					} else {
						cmd.reply <- result{fin: true}
					}
				case 'x':
					cmd.reply <- result{}
					return
				default:
					cmd.reply <- result{err: errProtocol}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	var buffer [8]byte
	n, err := s.Read(buffer[:])
	if err != nil || n != 4 || string(buffer[:n]) != "last" {
		t.Fatalf("lost final bytes, got %q n=%d err=%v", buffer[:n], n, err)
	}
	n, err = s.Read(buffer[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after final bytes, got n=%d err=%v", n, err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("final EOF did not release the stream")
	}
	if c.active != 0 {
		t.Fatalf("Neqo active request leaked on EOF: %d", c.active)
	}
}
