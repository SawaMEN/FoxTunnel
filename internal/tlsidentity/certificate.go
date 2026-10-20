package tlsidentity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"time"
)

// CertificateStore retains the last valid certificate/key pair. A reload only
// affects new handshakes; callers must not mutate certificates returned by Get.
// Session resumption can retain the previous authenticated TLS session.
type CertificateStore struct {
	certFile, keyFile string
	current           atomic.Pointer[tls.Certificate]
}

func NewCertificateStore(certFile, keyFile string) (*CertificateStore, error) {
	store := &CertificateStore{certFile: certFile, keyFile: keyFile}
	if err := store.Reload(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *CertificateStore) Reload() error {
	pair, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return errors.New("cannot load matching TLS certificate and key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("invalid TLS leaf certificate")
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return errors.New("TLS certificate is outside its validity period")
	}
	pair.Leaf = leaf
	s.current.Store(&pair)
	return nil
}

func (s *CertificateStore) Get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if pair := s.current.Load(); pair != nil {
		return pair, nil
	}
	return nil, errors.New("TLS certificate unavailable")
}
