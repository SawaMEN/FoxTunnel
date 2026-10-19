// This fixture serves QUIC/HTTP3 over localhost with a self-signed certificate.
// Neqo must reject that certificate: no HTTP request should be sent.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { log.Fatal(err) }
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2026),
		Subject: pkix.Name{CommonName: "example.org"},
		DNSNames: []string{"example.org"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil { log.Fatal(err) }
	ln, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil { log.Fatal(err) }
	defer ln.Close()
	srv := &http3.Server{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			NextProtos: []string{http3.NextProtoH3},
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Sending HTTP requests before certificate verification would be a
			// protocol security violation in this experimental integration.
			fmt.Fprintln(os.Stderr, "ERROR: unauthenticated HTTP request received")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}),
	}
	fmt.Println(ln.LocalAddr().(*net.UDPAddr).Port)
	if err := os.Stdout.Sync(); err != nil { log.Fatal(err) }
	if err := srv.Serve(ln); err != nil { log.Fatal(err) }
}
