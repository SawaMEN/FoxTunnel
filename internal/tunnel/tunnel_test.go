package tunnel

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEndToEndSOCKSOverH2(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	upstream := httptest.NewUnstartedServer(&Server{Username: "alice", Password: "secret", AllowPrivate: true})
	upstream.EnableHTTP2 = true
	upstream.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	upstream.StartTLS()
	defer upstream.Close()
	tmp := t.TempDir()
	pemCert := filepath.Join(tmp, "root.pem")
	if err := os.WriteFile(pemCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(upstream.URL, "alice", "secret", pemCert)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	socks, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	go func() { _ = client.Serve(socks) }()
	conn, err := net.DialTimeout("tcp", socks.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatal(err)
	}
	if greeting[0] != 5 || greeting[1] != 0 {
		t.Fatalf("unexpected SOCKS method: %v", greeting)
	}
	ip := net.ParseIP("127.0.0.1").To4()
	port := echo.Addr().(*net.TCPAddr).Port
	dst := append([]byte{5, 1, 0, 1}, ip...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(port))
	if _, err := conn.Write(dst); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("SOCKS connection failed: %v", reply)
	}
	msg := []byte("fox tunnel roundtrip")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("got %q", got)
	}
}

func TestRejectUnauthenticatedCONNECT(t *testing.T) {
	handler := &Server{Username: "a", Password: "b", AllowPrivate: true}
	req := httptest.NewRequest(http.MethodConnect, "https://example.com:443", nil)
	req.ProtoMajor = 2
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unauthenticated CONNECT, got %d", rr.Code)
	}
}

func TestInvalidCredentials(t *testing.T) {
	s := &Server{Username: "a", Password: "b"}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Header.Set("Proxy-Authorization", "Basic YTp3cm9uZw==")
	if s.authorized(req) {
		t.Fatal("accepted invalid password")
	}
	req.Header.Set("Proxy-Authorization", "Basic YTpi")
	if !s.authorized(req) {
		t.Fatal("rejected correct credentials")
	}
}

func TestUnsafeTargets(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.5", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "2001:db8::1"} {
		ip := netip.MustParseAddr(raw)
		if safePublicIP(ip) {
			t.Errorf("IP %s must be denied", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !safePublicIP(netip.MustParseAddr(raw)) {
			t.Errorf("public IP %s denied", raw)
		}
	}
}

func TestInvalidTargets(t *testing.T) {
	for _, raw := range []string{"", "example.org", "example.org:0", "example.org:65536", ":443"} {
		if _, _, err := splitTarget(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
}
