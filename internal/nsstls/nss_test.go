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
