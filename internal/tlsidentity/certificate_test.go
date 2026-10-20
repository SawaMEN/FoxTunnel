package tlsidentity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writePair(t *testing.T, cert, key string, serial int64, expires time.Time) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: secret}), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestCertificateReloadRetainsLastValidPair(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if _, err := NewCertificateStore(cert, key); err == nil {
		t.Fatal("missing certificate accepted")
	}
	writePair(t, cert, key, 1, time.Now().Add(time.Hour))
	store, err := NewCertificateStore(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := store.Get(nil)
	keyBefore, _ := os.ReadFile(key)
	writePair(t, cert, key, 2, time.Now().Add(time.Hour))
	keyAfter, _ := os.ReadFile(key)
	os.WriteFile(key, keyBefore, 0600)
	if err := store.Reload(); err == nil {
		t.Fatal("mismatched key accepted")
	}
	got, _ := store.Get(nil)
	if got != old {
		t.Fatal("failed reload replaced active certificate")
	}
	os.WriteFile(key, keyAfter, 0600)
	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 1000 {
				pair, err := store.Get(nil)
				if err != nil || pair.Leaf == nil {
					t.Error("incomplete certificate published")
				}
			}
		}()
	}
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	readers.Wait()
	got, _ = store.Get(nil)
	if got.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("new pair unavailable")
	}
	writePair(t, cert, key, 3, time.Now().Add(-time.Minute))
	if err := store.Reload(); err == nil {
		t.Fatal("expired certificate accepted")
	}
	got, _ = store.Get(nil)
	if got.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("expired certificate replaced last valid pair")
	}
}
