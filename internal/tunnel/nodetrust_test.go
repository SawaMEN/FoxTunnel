package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
)

func TestExplicitNodePinsBoundToEveryOrigin(t *testing.T) {
	var endpoints [2]*httptest.Server
	for i := range endpoints {
		h := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		h.EnableHTTP2 = true
		h.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
		h.StartTLS()
		t.Cleanup(h.Close)
		endpoints[i] = h
	}
	ca := filepath.Join(t.TempDir(), "nodes-ca.pem")
	// Both local test endpoints may share httptest's built-in certificate.
	// The test separately pins the second origin to an intentionally wrong
	// key to verify that policies are selected by exact HTTPS origin.
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: endpoints[0].Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	pin := tlsidentity.Pin(endpoints[0].Certificate())
	wrong := tlsidentity.Pin(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("wrong public key")})
	cases := []struct {
		name string
		bad  bool
	}{
		{"valid", false},
		{"wrong second ingress", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewClient(endpoints[0].URL, "alice", "secret", ca)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.SetFallbackServers([]string{endpoints[1].URL}); err != nil {
				t.Fatal(err)
			}
			second := pin
			if tc.bad {
				second = wrong
			}
			payload, err := json.Marshal(nodePinsDocument{Version: 1, Nodes: []nodePinEntry{
				{URL: endpoints[0].URL, PinSHA256: pin},
				{URL: endpoints[1].URL, PinSHA256: second},
			}})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "pins.json")
			if err := os.WriteFile(path, payload, 0600); err != nil {
				t.Fatal(err)
			}
			if err := c.SetNodePinsFile(path); err != nil {
				t.Fatal(err)
			}
			// Ensure a primary-origin pin does not allow another entry
			// to bypass its independent configured mismatch.
			for i, endpoint := range endpoints {
				req, err := http.NewRequest(http.MethodGet, endpoint.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := c.transport.RoundTrip(req)
				if i == 1 && tc.bad {
					if err == nil {
						resp.Body.Close()
						t.Fatal("second node with wrong SPKI pin was accepted")
					}
					continue
				}
				if err != nil {
					t.Fatalf("trusted node %d: %v", i, err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					t.Fatalf("unexpected code %d", resp.StatusCode)
				}
			}
		})
	}
}

func TestNodePinsFailClosedOnMissingOrSymlinkedFile(t *testing.T) {
	c, err := NewClient("https://example.com", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetFallbackServers([]string{"https://b.example"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pins.json")
	missing := nodePinsDocument{Version: 1, Nodes: []nodePinEntry{{
		URL: "https://example.com",
		PinSHA256: tlsidentity.Pin(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("key")}),
	}}}
	b, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.SetNodePinsFile(path); err == nil {
		t.Fatal("incomplete pin manifest accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := c.SetNodePinsFile(path); err == nil {
		t.Fatal("world-readable trust policy accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "symlink.json")
	if err := os.Symlink(path, link); err == nil {
		if err := c.SetNodePinsFile(link); err == nil {
			t.Fatal("symbolic link trust policy accepted")
		}
	}
}
