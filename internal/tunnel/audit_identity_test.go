package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

func TestAuditPrimaryPinAppliesToDiscoveredOriginAlias(t *testing.T) {
	endpoint := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	endpoint.EnableHTTP2 = true
	endpoint.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	endpoint.StartTLS()
	defer endpoint.Close()
	c, err := NewClient(endpoint.URL, "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.tlsConfig.RootCAs.AddCert(endpoint.Certificate())
	wrong := tlsidentity.Pin(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("wrong key")})
	if err := c.SetServerIdentity("", wrong); err != nil {
		t.Fatal(err)
	}
	pool := c.transport.(*identityPool)
	u, _ := url.Parse(endpoint.URL)
	u.Host = u.Hostname() + ":0" + u.Port()
	view := identityView{pool: pool, policies: map[string]tlsidentity.Policy{u.String(): {}}}
	for _, origin := range []string{endpoint.URL, u.String()} {
		req, _ := http.NewRequest("GET", origin, nil)
		resp, err := view.RoundTrip(req)
		if resp != nil {
			resp.Body.Close()
		}
		if err == nil {
			t.Errorf("mandatory primary pin bypassed using %s", origin)
		}
	}
	if err := c.SetServerIdentity("", tlsidentity.Pin(endpoint.Certificate())); err != nil {
		t.Fatal(err)
	}
	view.pool = c.transport.(*identityPool)
	req, _ := http.NewRequest("GET", u.String(), nil)
	resp, err := view.RoundTrip(req)
	if err != nil {
		t.Fatal("correct primary pin rejected on equivalent origin:", err)
	}
	resp.Body.Close()
}
