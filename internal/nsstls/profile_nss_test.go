//go:build nss && cgo && linux

package nsstls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/SawaMEN/FoxTunnel/internal/fingerprint"
	"github.com/SawaMEN/FoxTunnel/internal/webprofile"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientProfileRuntimeRequirement(t *testing.T) {
	transport, err := NewTransportWithProfiles(&tls.Config{}, "", Firefox158)
	if Version() == "3.130" {
		if err != nil {
			t.Fatal(err)
		}
		transport.CloseIdleConnections()
	} else if err == nil {
		transport.CloseIdleConnections()
		t.Fatal("accepted a different NSS runtime")
	}
}
func requireFirefoxRuntime(t *testing.T) {
	t.Helper()
	if Version() != "3.130" {
		t.Skip("pinned NSS 3.130 is exercised in release CI")
	}
}
func TestClientProfileActualClientHelloAndSocketIsolation(t *testing.T) {
	requireFirefoxRuntime(t)
	capture := func(profile, protocol string) fingerprint.Hello {
		t.Helper()
		transport, e := NewTransport(&tls.Config{})
		if e != nil {
			t.Fatal(e)
		}
		transport.CloseIdleConnections()
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		observed := make(chan fingerprint.Hello, 1)
		go func() {
			c, e := l.Accept()
			if e != nil {
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			h, e := fingerprint.ReadClientHello(c)
			if e == nil {
				observed <- h
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// Capture only the outgoing ClientHello; the fixture intentionally
		// closes before the server handshake. No application bytes are sent.
		c, e := DialTLSContextWithProfile(ctx, "tcp", l.Addr().String(), &tls.Config{ServerName: "fixture.invalid", NextProtos: []string{protocol}}, profile)
		if e == nil {
			c.Close()
			t.Fatal("capture-only listener completed handshake")
		}
		select {
		case h := <-observed:
			return h
		case <-ctx.Done():
			t.Fatal("no ClientHello")
			return fingerprint.Hello{}
		}
	}
	baseline := capture("", "h2")
	expectedGroups := []uint16{4588, 29, 23, 24, 25}
	// NSS ssl3_FilterSigAlgs places PKCS#1 certificate schemes last for
	// TLS-1.3-only sockets. Preserve that real policy instead of rewriting bytes.
	expectedSignatures := []uint16{1027, 1283, 1539, 2052, 2053, 2054, 515, 1025, 1281, 1537, 513}
	for _, protocol := range []string{"h2", "http/1.1"} {
		got := capture(Firefox158, protocol)
		if !reflect.DeepEqual(got.SupportedGroups, expectedGroups) || !reflect.DeepEqual(got.KeyShareGroups, []uint16{4588, 29, 23}) || !reflect.DeepEqual(got.SignatureAlgorithms, expectedSignatures) {
			t.Fatalf("actual preferences: %+v", got)
		}
		if !reflect.DeepEqual(got.SupportedVersions, []uint16{772}) || !reflect.DeepEqual(got.ALPN, []string{protocol}) {
			t.Fatal("TLS/ALPN policy changed", got)
		}
	}
	if after := capture("", "h2"); !reflect.DeepEqual(after, baseline) {
		t.Fatal("profile changed process-global NSS defaults")
	}
}
func TestClientProfileNoTLSOrALPNDowngrade(t *testing.T) {
	requireFirefoxRuntime(t)
	for _, failure := range []string{"tls12", "alpn"} {
		t.Run(failure, func(t *testing.T) {
			var reached atomic.Bool
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
			server.EnableHTTP2 = failure == "tls12"
			if failure == "tls12" {
				server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
			}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			transport, e := NewTransportWithProfiles(&tls.Config{RootCAs: roots}, "", Firefox158)
			if e != nil {
				t.Fatal(e)
			}
			defer transport.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
			if response, e := transport.RoundTrip(req); e == nil {
				response.Body.Close()
				t.Fatal("accepted unsupported TLS/ALPN")
			}
			if reached.Load() {
				t.Fatal("sent HTTP before negotiation policy passed")
			}
		})
	}
}

func TestClientProfileReuseAndFreshHandshake(t *testing.T) {
	requireFirefoxRuntime(t)
	peers := make(chan string, 3)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.Version != tls.VersionTLS13 {
			t.Error("unexpected TLS version")
		}
		peers <- r.RemoteAddr
		w.Write([]byte("verified page"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport, e := NewTransportWithProfiles(&tls.Config{RootCAs: roots}, "firefox-158", Firefox158)
	if e != nil {
		t.Fatal(e)
	}
	defer transport.CloseIdleConnections()
	get := func() string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
		response, e := transport.RoundTrip(req)
		if e != nil {
			t.Fatal(e)
		}
		body, e := io.ReadAll(response.Body)
		response.Body.Close()
		if e != nil || string(body) != "verified page" || response.ProtoMajor != 2 {
			t.Fatal("bad page", e)
		}
		return <-peers
	}
	first, second := get(), get()
	if first != second {
		t.Fatal("sequential H2 requests did not reuse the connection")
	}
	transport.CloseIdleConnections()
	if third := get(); third == first {
		t.Fatal("closed idle connection was reused")
	}
}

func BenchmarkClientProfileHandshake(b *testing.B) {
	if Version() != "3.130" {
		b.Skip("requires pinned NSS runtime")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("page")) }))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	for _, profile := range []string{"", Firefox158} {
		name := profile
		if name == "" {
			name = "default"
		}
		b.Run(name, func(b *testing.B) {
			transport, e := NewTransportWithProfiles(&tls.Config{RootCAs: roots}, "", profile)
			if e != nil {
				b.Fatal(e)
			}
			defer transport.CloseIdleConnections()
			b.ReportAllocs()
			for b.Loop() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
				response, e := transport.RoundTrip(req)
				if e != nil {
					cancel()
					b.Fatal(e)
				}
				_, e = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				cancel()
				transport.CloseIdleConnections()
				if e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}

// A server selecting X25519 must not need a second ClientHello when that
// real key share was already offered. This verifies usable shares, not labels.
func TestClientProfileAvoidsHelloRetryForX25519(t *testing.T) {
	requireFirefoxRuntime(t)
	certificate := httptest.NewTLSServer(http.NotFoundHandler())
	defer certificate.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	for _, profile := range []string{"", Firefox158} {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		type observed struct {
			p webprofile.Profile
			e error
		}
		result := make(chan observed, 1)
		go func() {
			p, e := webprofile.Capture(l, &tls.Config{Certificates: certificate.TLS.Certificates, CurvePreferences: []tls.CurveID{tls.X25519}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("page")) }), "X25519 HRR test", 100*time.Millisecond)
			result <- observed{p, e}
		}()
		transport, e := NewTransportWithProfiles(&tls.Config{RootCAs: roots}, "", profile)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://"+l.Addr().String(), nil)
		response, e := transport.RoundTrip(req)
		if e != nil {
			cancel()
			l.Close()
			t.Fatal(e)
		}
		_, e = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		transport.CloseIdleConnections()
		cancel()
		if e != nil {
			l.Close()
			t.Fatal(e)
		}
		select {
		case capture := <-result:
			l.Close()
			if capture.e != nil {
				t.Fatal(capture.e)
			}
			hellos := 0
			for _, r := range capture.p.Records {
				if r.Direction == "client" && r.Type == 22 {
					hellos++
				}
			}
			expected := 2
			if profile == Firefox158 {
				expected = 1
			}
			if hellos != expected {
				t.Fatalf("profile %q: got %d ClientHello records, expected %d", profile, hellos, expected)
			}
		case <-time.After(3 * time.Second):
			l.Close()
			t.Fatal("capture did not complete")
		}
	}
}
