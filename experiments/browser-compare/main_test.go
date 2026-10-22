package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestControlledGETWorkloadAndResumptionObserver(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			dir := t.TempDir()
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
				DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			keyDER, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "out.json")
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err = serve(ctx, protocol, certPath, keyPath, filepath.Join(dir, "ready.json"), out, "go"); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			var result report
			if err = json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if !result.Complete || len(result.Connections) < 3 || result.Phases["cancel"].Canceled != 4 || result.Phases["parallel"].MaxActive < 2 {
				t.Fatalf("incomplete workload: %+v", result)
			}
			resumed := false
			for _, c := range result.Connections {
				if c.Resumed != nil && *c.Resumed {
					resumed = true
				}
				if protocol == "h2" && len(c.Requests) > 0 && (c.H2 == nil || len(c.H2.Hello.Extensions) == 0 || len(c.H2.Settings) == 0) {
					t.Fatal("missing raw H2/TLS field order")
				}
			}
			if !resumed {
				t.Fatal("positive control did not observe session resumption")
			}
		})
	}
}
