//go:build nss && cgo && linux

package nsstls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestHandshakeCancellation(t *testing.T) {
	if _, err := NewTransport(&tls.Config{}); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := wrap(ctx, raw, "localhost", x509.NewCertPool()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handshake cancellation: %v", err)
	}
}
func TestConcurrentCloseUnblocksRead(t *testing.T) {
	if _, err := NewTransport(&tls.Config{}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	raw, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := wrap(ctx, raw, "example.com", roots)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); var b [1]byte; _, _ = c.Read(b[:]) }()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = c.Close() }()
	}
	wg.Wait()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("NSS Read blocked after close")
	}
	if _, err := c.Write([]byte("closed")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
}
func TestALPNRequired(t *testing.T) {
	transport, err := NewTransport(&tls.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("HTTP/1 downgrade reached handler") }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	raw, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := wrap(ctx, raw, "example.com", roots); err == nil {
		c.Close()
		t.Fatal("accepted peer without h2 ALPN")
	}
}

var _ net.Conn = (*conn)(nil)
var _ io.Closer = (*conn)(nil)

func TestNilTLSConfigRejectsWithoutPanic(t *testing.T) {
	transport, err := NewTransportWithProfiles(nil, "", "")
	if err == nil || transport != nil {
		t.Fatalf("nil NSS TLS config accepted: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := DialTLSContextWithProfile(ctx, "tcp", "127.0.0.1:1", nil, "")
	if err == nil || conn != nil {
		t.Fatalf("nil NSS dial TLS config accepted: %v", err)
	}
}

func TestNSSHTTP2RejectsIncompatibleALPNAndTLSVersions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *tls.Config
	}{
		{"http11", &tls.Config{NextProtos: []string{"http/1.1"}}},
		{"mixed", &tls.Config{NextProtos: []string{"h2", "http/1.1"}}},
		{"tls12only", &tls.Config{MaxVersion: tls.VersionTLS12}},
		{"tls14minimum", &tls.Config{MinVersion: tls.VersionTLS13 + 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport, err := NewTransportWithProfiles(tc.config, "", "")
			if err == nil {
				if transport != nil {
					transport.CloseIdleConnections()
				}
				t.Fatal("accepted incompatible NSS HTTP/2 TLS settings")
			}
		})
	}
}
func TestNSSDialRejectsTLS12OnlyBeforeNetworkIO(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := DialTLSContextWithProfile(ctx, "tcp", "127.0.0.1:1",
		&tls.Config{MaxVersion: tls.VersionTLS12}, "")
	if err == nil || conn != nil {
		t.Fatalf("unsupported NSS 1.2-only connection accepted: %v", err)
	}
}

func TestNSSRejectsUnsupportedMutualTLSConfiguration(t *testing.T) {
	configs := []*tls.Config{
		{Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("test")}}}},
		{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tls.Certificate{}, nil
		}},
	}
	for _, config := range configs {
		transport, err := NewTransportWithProfiles(config, "", "")
		if err == nil {
			if transport != nil {
				transport.CloseIdleConnections()
			}
			t.Fatal("NSS accepted ignored client certificate policy")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := DialTLSContextWithProfile(ctx, "tcp", "127.0.0.1:1", config, "")
		cancel()
		if err == nil || conn != nil {
			t.Fatal("NSS direct dial accepted unsupported mTLS client certificate")
		}
	}
}

func TestNSSVerifierHonorsTLSConfigTime(t *testing.T) {
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	config := &tls.Config{
		RootCAs: roots,
		Time:    func() time.Time { return server.Certificate().NotBefore.Add(-time.Hour) },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := DialTLSContextWithProfile(ctx, "tcp", server.Listener.Addr().String(), config, "")
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("NSS ignored caller TLS verification time and accepted a not-yet-valid cert")
	}
}
