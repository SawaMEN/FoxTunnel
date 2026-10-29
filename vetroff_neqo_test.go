//go:build neqo && nss && cgo && linux && amd64

package vetroff_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ft "github.com/SawaMEN/VetroffProxy"
)

func TestPublicNeqoContextAndPin(t *testing.T) {
	t.Run("h3", func(t *testing.T) { testPublicNeqoContextAndPin(t, false) })
	t.Run("fallback", func(t *testing.T) { testPublicNeqoContextAndPin(t, true) })
}
func testPublicNeqoContextAndPin(t *testing.T, fallback bool) {
	credentials := ft.Credentials{Username: "sdk", Password: "test-only"}
	server, err := ft.NewServer(ft.ServerConfig{Credentials: credentials, AllowPrivateDestinations: true})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewUnstartedServer(server)
	endpoint.EnableHTTP2 = true
	endpoint.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	endpoint.StartTLS()
	defer endpoint.Close()
	if !fallback {
		packet, err := net.ListenPacket("udp", strings.TrimPrefix(endpoint.URL, "https://"))
		if err != nil {
			t.Fatal(err)
		}
		h3 := &http3.Server{Handler: server, TLSConfig: endpoint.TLS.Clone()}
		done := make(chan struct{})
		go func() { defer close(done); _ = h3.Serve(packet) }()
		defer func() { h3.Close(); packet.Close(); <-done }()
	}
	pin := sha256.Sum256(endpoint.Certificate().RawSubjectPublicKeyInfo)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: endpoint.Certificate().Raw}), 0600)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		_, _ = conn.Write(data)
	}()
	client, err := ft.NewClient(ft.ClientConfig{ServerURL: endpoint.URL, Credentials: credentials, CACertFile: ca, TLSBackend: "nss", Transport: "h3-post", QUICBackend: "neqo", H3Fallback: map[bool]string{false: "none", true: "h2"}[fallback], SPKIPin: "sha256/" + base64.StdEncoding.EncodeToString(pin[:]), QUICHandshakeTimeout: 150 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	conn, err := client.DialContext(ctx, "tcp", target.Addr().String())
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("public SDK Neqo fallback"), 16384)
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if err == nil {
			err = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		done <- err
	}()
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(payload, got) {
		t.Fatal("SDK transfer/half-close", len(got), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
