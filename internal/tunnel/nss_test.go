//go:build nss && cgo && linux

package tunnel

import (
	"bytes"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestNSSSOCKSOverHTTP2(t *testing.T) {
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
	if err := client.SetTLSBackend("nss"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, code := connectSOCKS(t, addr, target)
			defer conn.Close()
			if code != 0 {
				t.Errorf("NSS SOCKS failure: %d", code)
				return
			}
			msg := bytes.Repeat([]byte("NSS tunnel"), 32768)
			written := make(chan error, 1)
			go func() { _, err := conn.Write(msg); written <- err }()
			got := make([]byte, len(msg))
			_, err := io.ReadFull(conn, got)
			if err != nil || !bytes.Equal(got, msg) {
				t.Errorf("NSS payload: %v", err)
			}
			if err := <-written; err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
func TestNSSRejectsUntrustedAndWrongHostname(t *testing.T) {
	for _, kind := range []string{"untrusted", "hostname"} {
		t.Run(kind, func(t *testing.T) {
			reached := make(chan struct{}, 1)
			client, addr := testClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached <- struct{}{} }))
			if kind == "untrusted" {
				client.tlsConfig.RootCAs = x509.NewCertPool()
			} else {
				client.tlsConfig.ServerName = "wrong-host.invalid"
			}
			if err := client.SetTLSBackend("nss"); err != nil {
				t.Fatal(err)
			}
			conn, code := connectSOCKS(t, addr, "example.org:443")
			conn.Close()
			if code == 0 {
				t.Fatal("invalid certificate accepted")
			}
			select {
			case <-reached:
				t.Fatal("HTTP request sent before certificate verification")
			default:
			}
		})
	}
}
func TestNSSConnectSetupTimeout(t *testing.T) {
	done := make(chan struct{})
	client, addr := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done(); close(done) }))
	if err := client.SetTLSBackend("nss"); err != nil {
		t.Fatal(err)
	}
	client.ConnectTimeout = 500 * time.Millisecond
	conn, code := connectSOCKS(t, addr, "example.org:443")
	conn.Close()
	if code == 0 {
		t.Fatal("stalled NSS CONNECT succeeded")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("NSS CONNECT context leaked")
	}
}
func TestNSSHalfClose(t *testing.T) {
	target := testDestination(t, func(c net.Conn) { data, _ := io.ReadAll(c); _, _ = c.Write(data) })
	client, addr := testClient(t, &Server{Username: "alice", Password: "secret", AllowPrivate: true})
	if err := client.SetTLSBackend("nss"); err != nil {
		t.Fatal(err)
	}
	conn, code := connectSOCKS(t, addr, target)
	if code != 0 {
		t.Fatal(code)
	}
	_, err := conn.Write([]byte("NSS half-close"))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "NSS half-close" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func BenchmarkNSSTunnelRoundTrip(b *testing.B) { benchmarkTunnelRoundTrip(b, "nss") }

func TestNSSPaddingEndToEnd(t *testing.T) { testPaddingBackend(t, "nss") }

func BenchmarkNSSPaddedTunnelRoundTrip(b *testing.B) { benchmarkTunnelOptions(b, "nss", true) }

func TestNSSProxyFallback(t *testing.T)                     { testProxyFallback(t, "nss") }
func TestNSSFallbackStopsOnCertificateFailure(t *testing.T) { testFallbackCertificate(t, "nss") }

func TestEndpointSchedulingNSS(t *testing.T) { testEndpointScheduling(t, "nss") }

func TestBondedSOCKSNSS(t *testing.T)                { testBondedSOCKS(t, "nss") }
func TestDiscoveredBondedSOCKSNSS(t *testing.T)      { testBondedSOCKSMode(t, "nss", 8, true) }
func TestDiscoveryRejectsUnverifiedNSS(t *testing.T) { testDiscoveryRejectsUnverifiedTLS(t, "nss") }
func TestVerifiedSNIAndPinNSS(t *testing.T)          { testVerifiedSNIAndPin(t, "nss") }

func TestNSSNativeTransports(t *testing.T)   { testNativeTransports(t, "nss") }
func TestNSSNativeVerification(t *testing.T) { testNativeVerificationBeforeCredentials(t, "nss") }
func TestNSSNativeDiscoveredBond(t *testing.T) {
	for _, mode := range []string{"h2-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) { testBondedSOCKSNative(t, "nss", 8, true, mode) })
	}
}

func TestXHTTPSettingsNSS(t *testing.T) { testXHTTPSettings(t, "nss") }

func TestBondedLanesSOCKSNSS(t *testing.T) {
	testBondedSOCKSNativeLanes(t, "nss", 8, false, "h2-connect", true)
}

func BenchmarkNSSBondedDataPath(b *testing.B) {
	for _, mode := range []struct {
		name  string
		lanes bool
	}{{"rpc", false}, {"lanes", true}} {
		b.Run(mode.name+"/write137", func(b *testing.B) { benchmarkBondedProfile(b, 0, 8, mode.lanes, "nss", 137) })
		b.Run(mode.name+"/write32768", func(b *testing.B) { benchmarkBondedProfile(b, 0, 8, mode.lanes, "nss", 32768) })
	}
}

func TestNativeBondedLanesNSS(t *testing.T) {
	for _, mode := range []string{"h2-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) { testBondedSOCKSNativeLanes(t, "nss", 8, true, mode, true) })
	}
}
