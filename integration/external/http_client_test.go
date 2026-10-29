package consumer_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	ft "github.com/SawaMEN/VetroffProxy"
	"github.com/quic-go/quic-go/http3"
)

// Only exported Vetroff APIs are available in this independent module.
func publicProxy(t *testing.T, udp ...bool) (string, string, ft.Credentials, *atomic.Int64) {
	t.Helper()
	creds := ft.Credentials{Username: "external-sdk", Password: "laboratory-only-not-an-operator-secret"}
	handler, err := ft.NewServer(ft.ServerConfig{Credentials: creds, AllowPrivateDestinations: true, EnableUDP: len(udp) > 0 && udp[0]})
	if err != nil {
		t.Fatal(err)
	}
	var h3Requests atomic.Int64
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 3 {
			h3Requests.Add(1)
		}
		handler.ServeHTTP(w, r)
	})
	server := httptest.NewUnstartedServer(wrapped)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	packet, err := net.ListenPacket("udp4", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Server{Handler: wrapped, TLSConfig: server.TLS.Clone()}
	done := make(chan struct{})
	go func() { defer close(done); _ = h3.Serve(packet) }()
	t.Cleanup(func() {
		h3.Close()
		packet.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("public HTTP/3 host did not stop")
		}
	})
	ca := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return server.URL, ca, creds, &h3Requests
}

func applicationTransport(t *testing.T, client *ft.Client, route string, roots *x509.CertPool) *http.Transport {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, ForceAttemptHTTP2: true}
	if route == "direct-dial" {
		transport.DialContext = client.DialContext
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- client.ServeSOCKS(listener) }()
		t.Cleanup(func() {
			client.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("public SOCKS server did not stop")
			}
		})
		proxy, err := url.Parse("socks5h://" + listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func TestPublicHTTPClientIntegration(t *testing.T) {
	endpoint, ca, creds, h3Requests := publicProxy(t)
	for _, carrier := range []string{"h2-connect", "h2-post", "h3-post", "wss", "xhttp-packet-up", "xhttp-stream-up"} {
		for _, route := range []string{"direct-dial", "standard-socks5h"} {
			t.Run(carrier+"/"+route, func(t *testing.T) {
				beforeH3 := h3Requests.Load()
				started := make(chan struct{}, 1)
				cancelled := make(chan struct{}, 1)
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/cancel" {
						started <- struct{}{}
						<-r.Context().Done()
						cancelled <- struct{}{}
						return
					}
					w.Header().Set("X-Application-Origin", "external-sdk-test")
					io.Copy(w, io.LimitReader(r.Body, 65537))
				}))
				origin.EnableHTTP2 = true
				origin.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
				origin.StartTLS()
				t.Cleanup(origin.Close)
				roots := x509.NewCertPool()
				roots.AddCert(origin.Certificate())
				client, err := ft.NewClient(ft.ClientConfig{ServerURL: endpoint, Credentials: creds,
					CACertFile: ca, TLSBackend: "go", Transport: carrier, ConnectTimeout: 3 * time.Second})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { client.Close() })
				httpClient := &http.Client{Transport: applicationTransport(t, client, route, roots), Timeout: 5 * time.Second}
				payload := bytes.Repeat([]byte("verified-application-payload/"), 1024)
				response, err := httpClient.Post(origin.URL+"/echo", "application/octet-stream", bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(io.LimitReader(response.Body, 65537))
				response.Body.Close()
				if err != nil || response.StatusCode != 200 || response.ProtoMajor != 2 ||
					response.Header.Get("X-Application-Origin") != "external-sdk-test" || !bytes.Equal(got, payload) {
					t.Fatal("application HTTP/2 response or payload failed", err)
				}
				if carrier == "h3-post" && h3Requests.Load() <= beforeH3 {
					t.Fatal("successful payload did not traverse a real HTTP/3 request")
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				request, _ := http.NewRequestWithContext(ctx, "GET", origin.URL+"/cancel", nil)
				finished := make(chan error, 1)
				go func() {
					r, err := httpClient.Do(request)
					if r != nil {
						r.Body.Close()
					}
					finished <- err
				}()
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("application did not receive request")
				}
				cancel()
				select {
				case err := <-finished:
					if !errors.Is(err, context.Canceled) {
						t.Fatal("HTTP cancellation lost", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("application request did not cancel")
				}
				select {
				case <-cancelled:
				case <-time.After(3 * time.Second):
					t.Fatal("origin did not observe cancellation")
				}
				client.Close()
				if conn, err := client.DialContext(context.Background(), "tcp", origin.Listener.Addr().String()); !errors.Is(err, net.ErrClosed) {
					if conn != nil {
						conn.Close()
					}
					t.Fatal("closed SDK client accepted another dial", err)
				}
			})
		}
	}
}

func TestPublicTrustAndAuthorizationBeforeApplication(t *testing.T) {
	endpoint, ca, creds, _ := publicProxy(t)
	var reached atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer origin.Close()
	for _, carrier := range []string{"h2-connect", "h3-post"} {
		for _, refusal := range []string{"hostname", "credentials"} {
			t.Run(carrier+"/"+refusal, func(t *testing.T) {
				config := ft.ClientConfig{ServerURL: endpoint, Credentials: creds, CACertFile: ca,
					TLSBackend: "go", Transport: carrier, ConnectTimeout: 3 * time.Second}
				if refusal == "hostname" {
					config.ServerName = "wrong-server.invalid"
				} else {
					config.Credentials.Password = "wrong-password"
				}
				client, err := ft.NewClient(config)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				httpClient := &http.Client{Transport: applicationTransport(t, client, "direct-dial", nil), Timeout: 5 * time.Second}
				response, err := httpClient.Get(origin.URL)
				if response != nil {
					response.Body.Close()
				}
				if err == nil || reached.Load() != 0 {
					t.Fatal("untrusted/unauthorized carrier reached application")
				}
			})
		}
	}
}
