package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// Verifies actual UDP QUIC + TLS 1.3/H3, not synthetic HTTP ProtoMajor=3.
// Public GET and rejected POST must remain distinct from an authorized SOCKS
// tunnel sharing the same HTTP/3 server and certificate.
func TestStage5CoverAndTunnelRealQUIC(t *testing.T) {
	root := t.TempDir()
	index := []byte("<html>Ordinary HTTPS/3 public page</html>")
	if err := os.WriteFile(filepath.Join(root, "index.html"), index, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".private"), []byte("never-visible"), 0600); err != nil {
		t.Fatal(err)
	}
	cover, err := NewCover(root)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Username: "alice", Password: "secret", AllowPrivate: true,
		MaxCoverRequests: 2, MaxTunnels: 2, Cover: cover,
	}
	client, socks := testClient(t, server)
	endpoint := setupEndpoint(t, client, server)
	startNativeH3(t, endpoint, server)
	usePrimary(t, client, endpoint.URL)
	if err := client.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	if err := client.SetTransport("h3-post"); err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(endpoint.Certificate())
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		QUICConfig:      quicConfig(),
	}
	defer transport.Close()
	public := &http.Client{Transport: transport, Timeout: 7 * time.Second}

	request := func(method, path string, authenticated bool) (*http.Response, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, endpoint.URL+path, nil)
		if err != nil {
			return nil, nil, err
		}
		if authenticated {
			req.Header.Set("Proxy-Authorization", stage2Basic("alice", "secret"))
		} else {
			req.Header.Set("Proxy-Authorization", stage2Basic("alice", "incorrect"))
		}
		req.Header.Set("X-FoxTunnel-Padding", "initial-v1")
		req.Header.Set(targetHeader, "private.example:443")
		resp, err := public.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp, body, err
	}

	// Server is started asynchronously by the established H3 test fixture.
	// Retry only startup connection errors, never an unexpected HTTP response.
	var page *http.Response
	var body []byte
	for attempt := 0; attempt < 15; attempt++ {
		page, body, err = request(http.MethodGet, "/", false)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("H3 public page unreachable:", err)
	}
	if page.StatusCode != http.StatusOK || page.ProtoMajor != 3 ||
		page.TLS == nil || page.TLS.Version != tls.VersionTLS13 ||
		!bytes.Equal(body, index) {
		t.Fatalf("H3 public page mismatch: status=%d proto=%s tls=%v body=%q",
			page.StatusCode, page.Proto, page.TLS, body)
	}
	if page.TLS.NegotiatedProtocol != http3.NextProtoH3 {
		t.Fatalf("H3 ALPN not negotiated: %q", page.TLS.NegotiatedProtocol)
	}
	head, body, err := request(http.MethodHead, "/", false)
	if err != nil || head.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("public H3 HEAD: status=%v body=%q err=%v", head, body, err)
	}
	private, body, err := request(http.MethodGet, "/.private", false)
	if err != nil || private.StatusCode != http.StatusNotFound ||
		bytes.Contains(body, []byte("never-visible")) {
		t.Fatalf("H3 dotfile exposed: %v %q %v", private, body, err)
	}
	probe, body, err := request(http.MethodPost, postPath, false)
	if err != nil || probe.StatusCode != http.StatusNotFound ||
		bytes.Contains(body, []byte("private.example")) {
		t.Fatalf("H3 unauthorized POST escaped cover: %v %q %v", probe, body, err)
	}
	if server.activeTunnels.Load() != 0 || server.activeCoverRequests.Load() != 0 {
		t.Fatal("unauthorized H3 requests consumed tunnel/cover resources")
	}

	target := testDestination(t, func(c net.Conn) {
		data, _ := io.ReadAll(c)
		_, _ = c.Write(data)
	})
	conn, code := connectSOCKS(t, socks, target)
	if code != 0 {
		t.Fatalf("authenticated H3 SOCKS CONNECT refused: %d", code)
	}
	payload := bytes.Repeat([]byte("authenticated QUIC stream"), 2048)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("authenticated H3 echo corrupted: bytes=%d err=%v", len(received), err)
	}
	_ = conn.Close()
	for until := time.Now().Add(2 * time.Second); time.Now().Before(until); {
		if server.activeTunnels.Load() == 0 && server.activeCoverRequests.Load() == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("H3 stream cleanup incomplete: tunnels=%d cover=%d",
		server.activeTunnels.Load(), server.activeCoverRequests.Load())
}
