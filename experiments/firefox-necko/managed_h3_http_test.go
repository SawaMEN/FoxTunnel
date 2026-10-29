package firefox

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// These gates intentionally require the rebuilt verified bundle. Merely
// rejecting a missing forceHTTP3 API on an old runtime is not H3 validation.
func TestGeckoManagedHTTP3(t *testing.T) {
	bundle := os.Getenv("VETROFF_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified H3-only native API bundle required")
	}
	var requests, tcp atomic.Int32
	cfg := nativeProxyConfigured(t, "h3-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 || r.Header.Get("Proxy-Authorization") == "" {
			http.Error(w, "native H3 required", 400)
			return
		}
		requests.Add(1)
		w.Header().Set("X-Native-H3", "yes")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		if r.Method == "GET" {
			w.Write([]byte{0, 255, 128, 42})
			return
		}
		io.Copy(flushingWriter{w}, r.Body)
	}), func(server *httptest.Server) {
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				tcp.Add(1)
			}
		}
	})
	m, err := NewManaged(bundle, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", cfg.Server+"/h3-get", nil)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.ProtoMajor != 3 || !bytes.Equal(got, []byte{0, 255, 128, 42}) {
		t.Fatal("native H3 GET", resp.ProtoMajor, err)
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, _ = http.NewRequestWithContext(ctx, "POST", cfg.Server+"/h3-duplex", reader)
	resp, err = m.RoundTrip(req)
	if err != nil {
		t.Fatal("H3 headers must precede upload", err)
	}
	defer resp.Body.Close()
	payload := bytes.Repeat([]byte{0, 255, 128, 42}, 128<<10)
	sent := make(chan error, 1)
	go func() { _, e := writer.Write(payload); writer.Close(); sent <- e }()
	got, err = io.ReadAll(resp.Body)
	if err != nil || !bytes.Equal(got, payload) || resp.ProtoMajor != 3 || resp.Header.Get("X-Native-H3") != "yes" {
		t.Fatal("native H3 duplex", len(got), err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if tcp.Load() != 0 {
		t.Fatal("H3 success raced a TCP connection", tcp.Load())
	}
	if requests.Load() != 2 {
		t.Fatal("native H3 request replayed")
	}
}

func TestGeckoManagedHTTP3NoTCPFallback(t *testing.T) {
	bundle := os.Getenv("VETROFF_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified H3-only native API bundle required")
	}
	var tcp, requests atomic.Int32
	certificate, ca := testCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(200) }))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			tcp.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := NewManaged(bundle, Config{Server: server.URL, Username: "u", Password: "p", CACert: caPath, Transport: "h3-connect", ConnectTimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	for _, operation := range []string{"GET", "POST", "UDP-v1", "UDP-v2"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var err error
			switch operation {
			case "UDP-v1":
				_, err = m.ExchangeUDP(ctx, []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 0xff})
			case "UDP-v2":
				var stream io.ReadWriteCloser
				stream, err = m.OpenUDPStream(ctx)
				if stream != nil {
					stream.Close()
				}
			default:
				var body io.Reader
				if operation == "POST" {
					body = bytes.NewReader([]byte{0, 255, 128, 42})
				}
				req, _ := http.NewRequestWithContext(ctx, operation, server.URL+"/h3-only", body)
				var resp *http.Response
				resp, err = m.RoundTrip(req)
				if resp != nil {
					resp.Body.Close()
				}
			}
			if err == nil {
				t.Fatal("H3 succeeded against a TCP-only origin")
			}
		})
	}
	if tcp.Load() != 0 || requests.Load() != 0 {
		t.Fatalf("H3-only operation raced/replayed TCP: accepts=%d requests=%d", tcp.Load(), requests.Load())
	}
}

func TestGeckoManagedHTTP3Trust(t *testing.T) {
	bundle := os.Getenv("VETROFF_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("verified H3-only native API bundle required")
	}
	var tcp, requests atomic.Int32
	cfg := nativeProxyConfigured(t, "h3-connect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(200)
	}), func(server *httptest.Server) {
		server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				tcp.Add(1)
			}
		}
	})
	_, wrongCA := testCertificate(t)
	cfg.CACert = filepath.Join(t.TempDir(), "untrusted-root.pem")
	if err := os.WriteFile(cfg.CACert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongCA}), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := NewManaged(bundle, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", cfg.Server+"/untrusted", nil)
	resp, err := m.RoundTrip(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("native H3 accepted an untrusted origin")
	}
	var network net.Error
	if errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("native H3 trust denial became retryable transport loss", err)
	}
	if tcp.Load() != 0 || requests.Load() != 0 {
		t.Fatal("untrusted H3 sent TCP or application bytes", tcp.Load(), requests.Load())
	}
}
