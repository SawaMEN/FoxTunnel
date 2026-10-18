package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

func TestPinCannotReuseAnotherOriginsSessionTicket(t *testing.T) {
	var ticket [32]byte
	if _, err := rand.Read(ticket[:]); err != nil {
		t.Fatal(err)
	}
	var resumed atomic.Bool
	makeEndpoint := func() (*httptest.Server, *x509.Certificate) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"vpn.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS.DidResume {
				resumed.Store(true)
			}
			w.WriteHeader(204)
		}))
		s.EnableHTTP2 = true
		s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
		s.TLS.SetSessionTicketKeys([][32]byte{ticket})
		s.StartTLS()
		t.Cleanup(s.Close)
		return s, cert
	}
	a, aCert := makeEndpoint()
	b, bCert := makeEndpoint()
	c, err := NewClient(a.URL, "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Session resumption is currently a Go TLS feature; NSS disables tickets.
	if err := c.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	c.tlsConfig.RootCAs.AddCert(aCert)
	c.tlsConfig.RootCAs.AddCert(bCert)
	policy := tlsidentity.Policy{SNI: "vpn.example", PinSHA256: tlsidentity.Pin(aCert)}
	if err := c.SetServerIdentity(policy.SNI, policy.PinSHA256); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		r, _ := http.NewRequest("GET", a.URL, nil)
		resp, err := c.transport.RoundTrip(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		c.transport.CloseIdleConnections()
	}
	if !resumed.Load() {
		t.Fatal("test did not establish resumption")
	}
	pool := c.transport.(*identityPool)
	view := identityView{pool: pool, policies: map[string]tlsidentity.Policy{b.URL: policy}}
	r, _ := http.NewRequest("GET", b.URL, nil)
	resp, err := view.RoundTrip(r)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("shared ticket key bypassed origin SPKI pin")
	}
}

func TestVerifiedSNIAndPinGo(t *testing.T) { testVerifiedSNIAndPin(t, "go") }
func testVerifiedSNIAndPin(t *testing.T, backend string) {
	var calls atomic.Int64
	c, _ := testClient(t, &Server{Username: "alice", Password: "secret"})
	endpoint := setupEndpoint(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS.ServerName != "example.com" || r.Host != "example.com" {
			t.Error("SNI/HTTP authority not applied", r.TLS.ServerName, r.Host)
		}
		w.WriteHeader(204)
	}))
	usePrimary(t, c, endpoint.URL)
	if err := c.SetTLSBackend(backend); err != nil {
		t.Fatal(err)
	}
	pin := tlsidentity.Pin(endpoint.Certificate())
	request := func() error {
		req, _ := http.NewRequest("GET", endpoint.URL, nil)
		resp, err := c.transport.RoundTrip(req)
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		return err
	}
	if err := c.SetServerIdentity("example.com", pin); err != nil {
		t.Fatal(err)
	}
	if err := request(); err != nil {
		t.Fatal("verified custom SNI failed", err)
	}
	before := calls.Load()
	wrong := tlsidentity.Pin(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("different key")})
	for _, policy := range [][2]string{{"example.com", wrong}, {"wrong.example", pin}} {
		if err := c.SetServerIdentity(policy[0], policy[1]); err != nil {
			t.Fatal(err)
		}
		if err := request(); err == nil || !terminalSetupError(err) {
			t.Fatal("identity error was bypassable", err)
		}
	}
	c.tlsConfig.RootCAs = x509.NewCertPool()
	if err := c.SetServerIdentity("example.com", pin); err != nil {
		t.Fatal(err)
	}
	if err := request(); err == nil {
		t.Fatal("pin replaced CA verification")
	}
	if calls.Load() != before {
		t.Fatal("HTTP sent before verification")
	}
	if err := c.SetServerIdentity(strings.Repeat("x", 254), pin); err == nil {
		t.Fatal("oversized SNI accepted")
	}
}

func TestIdentityPoolDoesNotApplyPrimarySNIToFallback(t *testing.T) {
	c, _ := testClient(t, &Server{Username: "alice", Password: "secret"})
	a := setupEndpoint(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	b := setupEndpoint(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "" {
			t.Error("primary SNI leaked to fallback", r.TLS.ServerName)
		}
		w.WriteHeader(204)
	}))
	usePrimary(t, c, a.URL)
	if err := c.SetServerIdentity("example.com", tlsidentity.Pin(a.Certificate())); err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", b.URL, nil)
	resp, err := c.transport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
