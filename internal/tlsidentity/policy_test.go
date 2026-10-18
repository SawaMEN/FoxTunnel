package tlsidentity

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
)

func TestPolicyBoundsAndPin(t *testing.T) {
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("public key")}
	pin := Pin(cert)
	p, err := Normalize("VPN.Example", pin)
	if err != nil || p.SNI != "vpn.example" {
		t.Fatal("normalization", err)
	}
	for _, name := range []string{"127.0.0.1", "*.example", "a..example", "https://vpn.example", "vpn.example:443", "vpn.example\x00", "-a.example", strings.Repeat("a", 64) + ".example"} {
		if _, err := Normalize(name, pin); err == nil {
			t.Fatal("invalid SNI accepted", name)
		}
	}
	for _, pin := range []string{"invalid", "sha256/AA==", "sha256/" + strings.Repeat("A", 44)} {
		if _, err := Normalize("", pin); err == nil {
			t.Fatal("invalid pin accepted")
		}
	}
	c := &tls.Config{}
	p.Apply(c)
	if c.InsecureSkipVerify || c.ServerName != p.SNI {
		t.Fatal("identity changed verification policy")
	}
	if err := c.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}); err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{RawSubjectPublicKeyInfo: []byte("other")}}}); err == nil {
		t.Fatal("wrong key accepted")
	}
}
