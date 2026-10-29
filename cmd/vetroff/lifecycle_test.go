package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/tlsidentity"
	"github.com/SawaMEN/VetroffProxy/internal/tunnel"
	"github.com/quic-go/quic-go/http3"
)

func operationPair(t *testing.T, certPath, keyPath string, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestServerCertificateReloadAndShutdownH2H3(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(operationPair(t, cert, key, 1))
	store, err := tlsidentity.NewCertificateStore(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	heldClosed := make(chan struct{}, 2)
	handler := &tunnel.Server{Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("operational"))
		if r.URL.Path == "/hold" {
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			heldClosed <- struct{}{}
		}
	})}
	server := &http.Server{Handler: handler, TLSConfig: serverTLS(store.Get), ReadHeaderTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serveListeners(ctx, server, handler, tcp, udp, 16) }()
	// Each request uses a fresh transport, disabling resumption and connection
	// reuse so the check proves the certificate used by a new TLS handshake.
	probe := func(mode string, want int64) {
		t.Helper()
		config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
		var transport http.RoundTripper
		if mode == "h3" {
			tr := &http3.Transport{TLSClientConfig: config}
			defer tr.Close()
			transport = tr
		} else {
			tr := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true}
			defer tr.CloseIdleConnections()
			transport = tr
		}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, err := client.Get("https://" + tcp.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != "operational" || response.TLS.PeerCertificates[0].SerialNumber.Int64() != want {
			t.Fatalf("%s certificate/body mismatch: %v", mode, err)
		}
		if mode == "h2" && response.ProtoMajor != 2 || mode == "h3" && response.ProtoMajor != 3 {
			t.Fatalf("unexpected protocol %s", response.Proto)
		}
	}
	for _, mode := range []string{"h2", "h3"} {
		probe(mode, 1)
	}
	roots.AppendCertsFromPEM(operationPair(t, cert, key, 2))
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"h2", "h3"} {
		probe(mode, 2)
	}
	os.WriteFile(key, []byte("broken"), 0600)
	if err := store.Reload(); err == nil {
		t.Fatal("broken renewal accepted")
	}
	for _, mode := range []string{"h2", "h3"} {
		probe(mode, 2)
	}
	// Leave one real request open on each carrier while stopping the server.
	h2 := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, ForceAttemptHTTP2: true}
	defer h2.CloseIdleConnections()
	h3 := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer h3.Close()
	for _, transport := range []http.RoundTripper{h2, h3} {
		client := &http.Client{Transport: transport, Timeout: 6 * time.Second}
		response, err := client.Get("https://" + tcp.Addr().String() + "/hold")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
	}
	cancel()
	for range 2 {
		select {
		case <-heldClosed:
		case <-time.After(2 * time.Second):
			t.Fatal("active request survived server cancellation")
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("server failed to stop")
	}
	// Successful rebinding proves both listeners were released.
	freshTCP, err := net.Listen("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	freshTCP.Close()
	freshUDP, err := net.ListenPacket("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	freshUDP.Close()
}
