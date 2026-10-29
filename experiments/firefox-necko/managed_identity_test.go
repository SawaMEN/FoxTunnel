package firefox

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/tlsidentity"
	"github.com/SawaMEN/VetroffProxy/internal/tunnel"
	"github.com/SawaMEN/VetroffProxy/internal/udpproto"
	"github.com/SawaMEN/VetroffProxy/internal/webprofile"
)

func TestNativeIdentityConfiguration(t *testing.T) {
	base := Config{Server: "https://127.0.0.1:443", Username: "u", Password: "p", ServerName: "IDENTITY.INVALID", SPKIPin: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", TLSClientProfile: "firefox-158", HTTP2ReceiveProfile: "firefox-158"}
	cfg, err := base.normalize()
	if err != nil || cfg.ServerName != "identity.invalid" {
		t.Fatal(cfg.ServerName, err)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.ServerName = "127.0.0.1" }, func(c *Config) { c.SPKIPin = "sha256/bad" }, func(c *Config) { c.Transport = "h3-connect" }, func(c *Config) { c.TLSClientProfile = "ignored" }, func(c *Config) { c.HTTP2ReceiveProfile = "ignored" }} {
		c := base
		mutate(&c)
		if _, err := c.normalize(); err == nil {
			t.Fatal("accepted invalid identity/profile")
		}
	}
}

// All positive and negative identity gates use the rebuilt verified bundle.
// The leaf has a DNS SAN only; dialing its numeric IP must require real SNI.
func TestGeckoManagedHTTPIdentity(t *testing.T) {
	bundle := os.Getenv("VETROFF_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("rebuilt verified identity bundle required")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			for _, fault := range []string{"valid", "wrong-pin", "wrong-name", "missing-name", "wrong-ca"} {
				t.Run(fault, func(t *testing.T) {
					certificate, ca := testCertificate(t, "identity.invalid")
					leaf, err := x509.ParseCertificate(certificate.Certificate[0])
					if err != nil {
						t.Fatal(err)
					}
					var requests atomic.Int32
					var sni atomic.Value
					proxy := &tunnel.Server{Username: "u", Password: "p", AllowPrivate: true, EnableUDP: true}
					handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if r.URL.Path == "/identity" {
							w.Header().Set("X-Request-Host", r.Host)
							w.WriteHeader(200)
							io.Copy(w, r.Body)
							return
						}
						proxy.ServeHTTP(w, r)
					})
					cfg := nativeProxyConfigured(t, mode, handler, func(s *httptest.Server) {
						s.TLS.Certificates = []tls.Certificate{certificate}
						s.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni.Store(hello.ServerName); return nil, nil }
					})
					if fault == "wrong-ca" {
						_, ca = testCertificate(t)
					}
					cfg.CACert = filepath.Join(t.TempDir(), "identity-root.pem")
					if err = os.WriteFile(cfg.CACert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), 0600); err != nil {
						t.Fatal(err)
					}
					cfg.ServerName = "identity.invalid"
					cfg.SPKIPin = tlsidentity.Pin(leaf)
					switch fault {
					case "wrong-pin":
						cfg.SPKIPin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
					case "wrong-name":
						cfg.ServerName = "other.invalid"
					case "missing-name":
						cfg.ServerName = ""
					}
					if fault != "valid" {
						cfg.ConnectTimeoutMS = 3000
					}
					m, err := NewManaged(bundle, cfg)
					if err != nil {
						t.Fatal(err)
					}
					defer m.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					payload := []byte{0, 255, 13, 10, 128, 42}
					req, _ := http.NewRequestWithContext(ctx, "POST", cfg.Server+"/identity", bytes.NewReader(payload))
					resp, err := m.RoundTrip(req)
					if fault != "valid" {
						if resp != nil {
							resp.Body.Close()
						}
						if err == nil {
							t.Fatal("accepted invalid server identity")
						}
						var network net.Error
						if errors.As(err, &network) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
							t.Fatal("identity denial became retryable network failure", err)
						}
						if conn, e := m.DialContext(ctx, "tcp", nativeEcho(t)); e == nil {
							conn.Close()
							t.Fatal("CONNECT accepted denied peer")
						}
						wire, e := udpproto.Encode(udpproto.Packet{Host: "127.0.0.1", Port: 9, Data: []byte{42}})
						if e != nil {
							t.Fatal(e)
						}
						if _, e = m.ExchangeUDP(ctx, wire); e == nil {
							t.Fatal("UDP-v1 accepted denied peer")
						}
						if stream, e := m.OpenUDPStream(ctx); e == nil {
							stream.Close()
							t.Fatal("UDP-v2 accepted denied peer")
						}
						if ctx.Err() != nil {
							t.Fatal("identity gate exhausted its context before exercising all carriers", ctx.Err())
						}
						if requests.Load() != 0 {
							t.Fatal("application request/authorization reached denied peer")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatal("native identity POST", err)
					}
					reqHost, _ := http.NewRequest("GET", cfg.Server, nil)
					if resp.Header.Get("X-Request-Host") != reqHost.URL.Host {
						t.Fatal("SNI rewrote HTTP authority")
					}
					if sni.Load() != "identity.invalid" {
						t.Fatal("native TLS did not send configured SNI", sni.Load())
					}
					conn, err := m.DialContext(ctx, "tcp", nativeEcho(t))
					if err != nil {
						t.Fatal(err)
					}
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					conn.Write(payload)
					conn.(interface{ CloseWrite() error }).CloseWrite()
					got, err = io.ReadAll(conn)
					conn.Close()
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatal("identity CONNECT", err)
					}
					echo := managedUDPEcho(t)
					packet := udpproto.Packet{Host: "127.0.0.1", Port: uint16(echo.LocalAddr().(*net.UDPAddr).Port), Data: payload}
					wire, err := udpproto.Encode(packet)
					if err != nil {
						t.Fatal(err)
					}
					reply, err := m.ExchangeUDP(ctx, wire)
					if err != nil {
						t.Fatal("identity UDP-v1", err)
					}
					decoded, err := udpproto.Parse(reply)
					if err != nil || !bytes.Equal(decoded.Data, payload) {
						t.Fatal("identity UDP-v1 reply", err)
					}
					stream, err := m.OpenUDPStream(ctx)
					if err != nil {
						t.Fatal("identity UDP-v2", err)
					}
					defer stream.Close()
					if err = udpproto.WriteFrame(stream, wire); err != nil {
						t.Fatal(err)
					}
					reply, err = udpproto.ReadFrame(stream)
					if err != nil {
						t.Fatal(err)
					}
					decoded, err = udpproto.Parse(reply)
					if err != nil || !bytes.Equal(decoded.Data, payload) {
						t.Fatal("identity UDP-v2 reply", err)
					}
				})
			}
		})
	}
}

func TestGeckoManagedHTTPNativeProfiles(t *testing.T) {
	bundle := os.Getenv("VETROFF_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("rebuilt verified profile bundle required")
	}
	certificate, ca := testCertificate(t, "identity.invalid")
	leaf, _ := x509.ParseCertificate(certificate.Certificate[0])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type captureResult struct {
		p   webprofile.Profile
		err error
	}
	done := make(chan captureResult, 1)
	go func() {
		p, e := webprofile.Capture(listener, &tls.Config{Certificates: []tls.Certificate{certificate}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("profile")) }), "native-profile", 3*time.Second)
		done <- captureResult{p, e}
	}()
	caPath := filepath.Join(t.TempDir(), "profile-root.pem")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), 0600)
	cfg := Config{Server: "https://" + listener.Addr().String(), Username: "u", Password: "p", CACert: caPath, ServerName: "identity.invalid", SPKIPin: tlsidentity.Pin(leaf), TLSClientProfile: "firefox-158", HTTP2ReceiveProfile: "firefox-158"}
	m, err := NewManaged(bundle, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", cfg.Server+"/", nil)
	resp, err := m.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	m.Close()
	var measured captureResult
	select {
	case measured = <-done:
	case <-ctx.Done():
		t.Fatal("profile capture did not finish")
	}
	if measured.err != nil {
		t.Fatal(measured.err)
	}
	settings := map[uint16]uint32{}
	for _, s := range measured.p.Settings {
		settings[s.ID] = s.Value
	}
	if settings[1] != 65536 || settings[4] != 131072 || settings[5] != 16384 {
		t.Fatalf("native H2 receive profile not applied: %+v", settings)
	}
	found := false
	for _, n := range measured.p.ConnectionWindow {
		if n == 12517377 {
			found = true
		}
	}
	if !found {
		t.Fatal("native H2 connection credit", measured.p.ConnectionWindow)
	}
	if !bytes.Equal(u16ProfileBytes(measured.p.Hello.SupportedGroups), u16ProfileBytes([]uint16{4588, 29, 23, 24, 25})) {
		t.Fatal("native TLS group preset", measured.p.Hello.SupportedGroups)
	}
	// NSS ssl3_FilterSigAlgs moves PKCS#1 certificate schemes last on a
	// TLS-1.3-only socket, as in the existing native NSS profile gate.
	if !bytes.Equal(u16ProfileBytes(measured.p.Hello.SignatureAlgorithms), u16ProfileBytes([]uint16{1027, 1283, 1539, 2052, 2053, 2054, 515, 1025, 1281, 1537, 513})) {
		t.Fatal("native TLS signature preset", measured.p.Hello.SignatureAlgorithms)
	}
	if !bytes.Equal(u16ProfileBytes(measured.p.Hello.KeyShareGroups), u16ProfileBytes([]uint16{4588, 29, 23})) {
		t.Fatal("native TLS key share preset", measured.p.Hello.KeyShareGroups)
	}
	if !bytes.Equal(u16ProfileBytes(measured.p.Hello.SupportedVersions), u16ProfileBytes([]uint16{772})) {
		t.Fatal("native TLS version preset", measured.p.Hello.SupportedVersions)
	}
	if !measured.p.Hello.SNI {
		t.Fatal("missing SNI in profile capture")
	}
}

func u16ProfileBytes(values []uint16) []byte {
	out := make([]byte, 0, len(values)*2)
	for _, v := range values {
		out = append(out, byte(v>>8), byte(v))
	}
	return out
}

func TestGeckoManagedHTTPIdentityOriginScope(t *testing.T) {
	bundle := os.Getenv("VETROFF_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("rebuilt identity bundle required")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			var primaryRequests, alternateRequests atomic.Int32
			cert, ca := testCertificate(t, "identity.invalid")
			leaf, _ := x509.ParseCertificate(cert.Certificate[0])
			primary := nativeProxyConfigured(t, mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { primaryRequests.Add(1); w.Write([]byte("primary")) }), func(s *httptest.Server) { s.TLS.Certificates = []tls.Certificate{cert} })
			alternate := nativeProxy(t, mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { alternateRequests.Add(1); w.Write([]byte("alternate")) }))
			otherCA, e := os.ReadFile(alternate.CACert)
			if e != nil {
				t.Fatal(e)
			}
			primary.CACert = filepath.Join(t.TempDir(), "two-roots.pem")
			e = os.WriteFile(primary.CACert, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), otherCA...), 0600)
			if e != nil {
				t.Fatal(e)
			}
			primary.ServerName = "identity.invalid"
			primary.SPKIPin = tlsidentity.Pin(leaf)
			m, e := NewManaged(bundle, primary)
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			for _, endpoint := range []struct{ url, body string }{{alternate.Server, "alternate"}, {primary.Server, "primary"}, {alternate.Server, "alternate"}} {
				req, _ := http.NewRequestWithContext(ctx, "GET", endpoint.url+"/", nil)
				resp, e := m.RoundTrip(req)
				if e != nil {
					t.Fatal("origin-specific identity", e)
				}
				body, e := io.ReadAll(resp.Body)
				resp.Body.Close()
				if e != nil || string(body) != endpoint.body {
					t.Fatal("origin-specific transfer", e)
				}
			}
			if primaryRequests.Load() != 1 || alternateRequests.Load() != 2 {
				t.Fatal("unexpected native request replay")
			}
		})
	}
}

func TestNativeNodeIdentityNormalization(t *testing.T) {
	pin := "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	cfg := Config{Server: "https://EXAMPLE.invalid", Username: "u", Password: "p", NodePolicies: map[string]tlsidentity.Policy{"https://example.invalid:0443": {SNI: "CERT.INVALID", PinSHA256: pin}}}
	normalized, err := cfg.normalize()
	if err != nil {
		t.Fatal(err)
	}
	again, err := normalized.normalize()
	if err != nil || again.NodePolicies["https://example.invalid:443"].SNI != "cert.invalid" {
		t.Fatal("node identity normalization is not canonical/idempotent", err)
	}
	for _, nodes := range []map[string]tlsidentity.Policy{
		{"https://other.invalid": {PinSHA256: pin}},
		{"https://example.invalid": {}},
		{"https://example.invalid": {PinSHA256: pin}, "https://EXAMPLE.invalid:0443": {PinSHA256: pin}},
	} {
		cfg.NodePolicies = nodes
		if _, err := cfg.normalize(); err == nil {
			t.Fatal("accepted incomplete/ambiguous node identity")
		}
	}
}

func TestGeckoManagedHTTPNodePins(t *testing.T) {
	bundle := os.Getenv("VETROFF_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("rebuilt per-node identity bundle required")
	}
	for _, mode := range []string{"h2-connect", "h3-connect"} {
		t.Run(mode, func(t *testing.T) {
			for _, fault := range []string{"valid", "wrong-second-pin", "unlisted-origin"} {
				t.Run(fault, func(t *testing.T) {
					var counts [2]atomic.Int32
					configs := make([]Config, 2)
					pins := make([]string, 2)
					var roots []byte
					names := []string{"first.invalid", "second.invalid"}
					for i := range configs {
						cert, ca := testCertificate(t, names[i])
						leaf, _ := x509.ParseCertificate(cert.Certificate[0])
						pins[i] = tlsidentity.Pin(leaf)
						configs[i] = nativeProxyConfigured(t, mode, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { counts[i].Add(1); w.Write([]byte(names[i])) }), func(s *httptest.Server) { s.TLS.Certificates = []tls.Certificate{cert} })
						roots = append(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})...)
					}
					cfg := configs[0]
					cfg.CACert = filepath.Join(t.TempDir(), "node-roots.pem")
					os.WriteFile(cfg.CACert, roots, 0600)
					cfg.NodePolicies = map[string]tlsidentity.Policy{configs[0].Server: {SNI: names[0], PinSHA256: pins[0]}, configs[1].Server: {SNI: names[1], PinSHA256: pins[1]}}
					switch fault {
					case "wrong-second-pin":
						cfg.NodePolicies[configs[1].Server] = tlsidentity.Policy{SNI: names[1], PinSHA256: pins[0]}
					case "unlisted-origin":
						delete(cfg.NodePolicies, configs[1].Server)
					}
					m, err := NewManaged(bundle, cfg)
					if err != nil {
						t.Fatal(err)
					}
					defer m.Close()
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					for i := range configs {
						req, _ := http.NewRequestWithContext(ctx, "POST", configs[i].Server+"/", bytes.NewReader([]byte("never-before-pin")))
						resp, err := m.RoundTrip(req)
						if i == 1 && fault != "valid" {
							if resp != nil {
								resp.Body.Close()
							}
							if err == nil || counts[1].Load() != 0 {
								t.Fatal("node pin/membership failure leaked an application request", err)
							}
							continue
						}
						if err != nil {
							t.Fatal("independent node identity", err)
						}
						body, err := io.ReadAll(resp.Body)
						resp.Body.Close()
						if err != nil || string(body) != names[i] {
							t.Fatal("independent node reply", err)
						}
					}
				})
			}
		})
	}
}

// Call the native API directly so Go validation cannot hide errors in native
// DNS validation, bounds or immutable-policy checks.
func TestGeckoManagedHTTPIdentityPolicyAPI(t *testing.T) {
	bundle := os.Getenv("VETROFF_NECKO_BUNDLE")
	if bundle == "" {
		t.Skip("rebuilt verified identity API bundle required")
	}
	runtime, err := VerifyBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VETROFF_XPCSHELL", runtime)
	marker := "  registerEndpoint(cfg.proxy_host, cfg.proxy_port);"
	if strings.Count(string(clientScript), marker) != 1 {
		t.Fatal("native policy injection point changed")
	}
	script := strings.Replace(string(clientScript), marker, marker+`
  {
    const mustReject = args => {
      let rejected = false;
      try {nativeCertDB.registerVetroffPolicy(...args);} catch {rejected = true;}
      if (!rejected) throw new Error("native identity API accepted invalid policy");
    };
    const pin = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    for (const name of ["-bad.invalid", "bad-.invalid", "a..invalid", "127.0.0.1", "a".repeat(254)]) {
      mustReject(["policy.invalid", 443, name, pin, ""]);
    }
    for (const port of [0, -1, 65536]) {
      mustReject(["policy.invalid", port, "identity.invalid", pin, ""]);
    }
    for (const wrong of ["sha256/bad", "sha1/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "sha256/"+"A".repeat(44)]) {
      mustReject(["policy.invalid", 443, "identity.invalid", wrong, ""]);
    }
    mustReject(["policy.invalid",443,"identity.invalid",pin,"unknown-profile"]);
    mustReject(["policy.invalid",443,"","",""]);
    nativeCertDB.registerVetroffPolicy("policy.invalid",443,"identity.invalid",pin,"");
    nativeCertDB.registerVetroffPolicy("POLICY.INVALID",443,"identity.invalid",pin,"");
    mustReject(["policy.invalid",443,"other.invalid",pin,""]);
    mustReject(["policy.invalid",443,"identity.invalid","sha256/AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",""]);
    mustReject(["policy.invalid",443,"identity.invalid",pin,"firefox-158"]);
  }
`, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	helper := startOperationalHelperWithClient(t, ctx, Config{Server: "https://primary.invalid", Username: "u", Password: "p", Listen: "127.0.0.1:0"}, []byte(script))
	if helper.listen == "" {
		t.Fatal("native identity API gates did not reach readiness")
	}
}
