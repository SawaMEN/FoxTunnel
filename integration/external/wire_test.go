package consumer_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ft "github.com/SawaMEN/VetroffProxy"
)

// This peer uses only the documented HTTP contract and standard library.
// It deliberately does not call the Vetroff client or import internal codecs.
func TestRawHTTP2WireDraft(t *testing.T) {
	handler, err := ft.NewServer(ft.ServerConfig{RequireProtocolNegotiation: true, Credentials: ft.Credentials{Username: "alice", Password: "secret"}, AllowPrivateDestinations: true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = io.Copy(conn, conn)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, version := range []string{"vetroff-draft-999", "vetroff-draft-0"} {
		reader, writer := io.Pipe()
		request, err := http.NewRequestWithContext(ctx, http.MethodConnect, server.URL, reader)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = listener.Addr().String()
		request.Header.Set("Proxy-Authorization", "Basic YWxpY2U6c2VjcmV0")
		request.Header.Set("X-Vetroff-Version", version)
		request.Header.Set("X-Vetroff-Require", "tcp")
		response, err := transport.RoundTrip(request)
		if err != nil {
			reader.Close()
			writer.Close()
			t.Fatal(err)
		}
		if response.ProtoMajor != 2 {
			t.Fatal("test did not use real HTTP/2")
		}
		if version != "vetroff-draft-0" {
			response.Body.Close()
			reader.Close()
			writer.Close()
			if response.StatusCode != http.StatusUpgradeRequired {
				t.Fatal("future version accepted", response.StatusCode)
			}
			continue
		}
		if response.StatusCode != 200 || response.Header.Get("X-Vetroff-Version") != version || response.Header.Get("X-Vetroff-Capabilities") != "tcp" {
			response.Body.Close()
			reader.Close()
			writer.Close()
			t.Fatal("version/capabilities not confirmed", response.StatusCode, response.Header)
		}
		payload := []byte("independent wire peer")
		sent := make(chan error, 1)
		go func() {
			_, err := writer.Write(payload)
			if err == nil {
				err = writer.Close()
			}
			sent <- err
		}()
		got, err := io.ReadAll(response.Body)
		response.Body.Close()
		reader.Close()
		writer.Close()
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatal("raw HTTP/2 stream/half-close", err, string(got))
		}
		if err = <-sent; err != nil {
			t.Fatal(err)
		}
	}
}
