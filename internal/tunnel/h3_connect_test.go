package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/xhttp"
	"github.com/quic-go/quic-go/http3"
)

// Observe the request at an independent HTTP/3 decoder: an echo-only check
// would also pass if CONNECT were accidentally rewritten into the old POST.
func TestH3ClassicCONNECTWire(t *testing.T) {
	var calls atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.ProtoMajor != 3 || r.Method != http.MethodConnect || r.Host != "destination.invalid:443" || r.URL.Path != "" || r.URL.Scheme != "" || r.Header.Get(targetHeader) != "" {
			t.Errorf("expected authority-only H3 CONNECT: method=%s protocol=%s scheme=%q path=%q", r.Method, r.Proto, r.URL.Scheme, r.URL.Path)
		}
		if r.Header.Get("Proxy-Authorization") != "Basic test-only" {
			t.Error("missing authentication")
		}
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		_, _ = io.Copy(flushingWriter{w: w, flusher: w.(http.Flusher)}, r.Body)
	})
	tcp := httptest.NewTLSServer(handler)
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	server := &http3.Server{TLSConfig: tcp.TLS.Clone(), Handler: handler}
	defer server.Close()
	go func() { _ = server.Serve(udp) }()
	roots := x509.NewCertPool()
	roots.AddCert(tcp.Certificate())
	transport, err := makeNativeTransport("h3-connect", "go", &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, "", xhttp.Settings{}, "", "", quicSettings{})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte{0, 255, 13, 10}, 16384)
	r, _ := http.NewRequestWithContext(ctx, http.MethodConnect, tcp.URL, bytes.NewReader(payload))
	r.Host = "destination.invalid:443"
	r.Header.Set("Proxy-Authorization", "Basic test-only")
	resp, err := transport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(got, payload) || calls.Load() != 1 {
		t.Fatal("CONNECT payload or request count", len(got), calls.Load(), err)
	}
}
