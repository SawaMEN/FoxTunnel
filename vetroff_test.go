package vetroff_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	ft "github.com/SawaMEN/VetroffProxy"
)

func endpoint(t *testing.T, mode string, padding bool, limit int, backend ...string) (*ft.Client, string) {
	t.Helper()
	server, e := ft.NewServer(ft.ServerConfig{RequireProtocolNegotiation: true, Credentials: ft.Credentials{Username: "alice", Password: "secret"}, AllowPrivateDestinations: true, Padding: padding})
	if e != nil {
		t.Fatal(e)
	}
	h := httptest.NewUnstartedServer(server)
	h.EnableHTTP2 = true
	h.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	h.StartTLS()
	t.Cleanup(h.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	selected := "go"
	if len(backend) > 0 {
		selected = backend[0]
	}
	clientProfile := ""
	if len(backend) > 1 {
		clientProfile = backend[1]
	}
	client, e := ft.NewClient(ft.ClientConfig{RequireProtocolNegotiation: true, TLSClientProfile: clientProfile, TLSBackend: selected, ServerURL: h.URL, Credentials: ft.Credentials{Username: "alice", Password: "secret"}, CACertFile: ca, Transport: mode, Padding: padding, MaxConnections: limit, HTTP2ReceiveProfile: ft.HTTP2ReceiveFirefox158})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _ = c.SetDeadline(time.Now().Add(5 * time.Second)); _, _ = io.Copy(c, c) }()
		}
	}()
	return client, l.Addr().String()
}
func TestPublicDialHalfCloseAndSetupContext(t *testing.T) {
	testPublicDialHalfCloseAndSetupContext(t, "go")
}
func testPublicDialHalfCloseAndSetupContext(t *testing.T, backend string, clientProfiles ...string) {
	for _, mode := range []string{"h2-connect", "h2-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		for _, padding := range []bool{false, true} {
			t.Run(mode+map[bool]string{true: "/padded", false: "/plain"}[padding], func(t *testing.T) {
				clientProfile := ""
				if len(clientProfiles) > 0 {
					clientProfile = clientProfiles[0]
				}
				client, target := endpoint(t, mode, padding, 0, backend, clientProfile)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				c, e := client.DialContext(ctx, "tcp", target)
				cancel()
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				payload := bytes.Repeat([]byte("independent SDK"), 40000)
				done := make(chan error, 1)
				go func() {
					_, e := c.Write(payload)
					if e == nil {
						e = c.(interface{ CloseWrite() error }).CloseWrite()
					}
					done <- e
				}()
				got, e := io.ReadAll(c)
				if e != nil || !bytes.Equal(got, payload) {
					t.Fatal("half-close/context/echo", len(got), e)
				}
				if e = <-done; e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}
func TestPublicDeadlineResetAndClose(t *testing.T) {
	client, target := endpoint(t, "xhttp-packet-up", false, 1)
	c, e := client.DialContext(context.Background(), "tcp", target)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if _, e = client.DialContext(context.Background(), "tcp", target); !errors.Is(e, ft.ErrCapacity) {
		t.Fatal("missing capacity limit", e)
	}
	if got := client.Status().Operations.Rejections.SDKCapacity; got != 1 {
		t.Fatal("SDK capacity rejection was not recorded", got)
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	var b [1]byte
	if _, e = c.Read(b[:]); e == nil {
		t.Fatal("deadline ignored")
	} else if timeout, ok := e.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal("not a deadline error", e)
	}
	c.SetReadDeadline(time.Time{})
	if _, e = c.Write([]byte{7}); e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadFull(c, b[:]); e != nil || b[0] != 7 {
		t.Fatal("deadline reset destroyed stream", e)
	}
	if e = client.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Read(b[:]); e == nil {
		t.Fatal("client close left connection open")
	}
	if _, e = client.DialContext(context.Background(), "tcp", target); !errors.Is(e, net.ErrClosed) {
		t.Fatal("dial after close", e)
	}
}
func TestPublicSOCKSOwnership(t *testing.T) {
	client, _ := endpoint(t, "h2-connect", false, 0)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- client.ServeSOCKS(l) }()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{5, 1, 0})
	var reply [2]byte
	if _, e = io.ReadFull(c, reply[:]); e != nil || reply != [2]byte{5, 0} {
		t.Fatal("SOCKS greeting", e)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SOCKS listener retained")
	}
	if _, e = c.Read(reply[:]); e == nil {
		t.Fatal("SOCKS socket retained")
	}
}
func TestPublicServerTLSAndCredentials(t *testing.T) {
	s, e := ft.NewServer(ft.ServerConfig{Credentials: ft.Credentials{Username: "alice", Password: "secret"}})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("CONNECT", "http://example.org:443", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatal("plaintext accepted")
	}
	if _, e = ft.NewServer(ft.ServerConfig{}); e == nil {
		t.Fatal("empty auth accepted")
	}
	c, target := endpoint(t, "h2-connect", false, 0)
	if _, e = c.DialContext(context.Background(), "udp", target); e == nil {
		t.Fatal("UDP accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = c.DialContext(ctx, "tcp", target); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled setup", e)
	}
}

func TestPublicCloseCancelsPendingDial(t *testing.T) { testPublicCloseCancelsPendingDial(t, "go") }
func testPublicCloseCancelsPendingDial(t *testing.T, backend string) {
	started, closed := make(chan struct{}), make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(closed) }))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	client, e := ft.NewClient(ft.ClientConfig{ServerURL: server.URL, Credentials: ft.Credentials{Username: "alice", Password: "secret"}, CACertFile: ca, TLSBackend: backend, MaxConnections: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	result := make(chan error, 1)
	go func() {
		c, e := client.DialContext(context.Background(), "tcp", "example.org:443")
		if c != nil {
			c.Close()
		}
		result <- e
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("setup did not begin")
	}
	if _, e := client.DialContext(context.Background(), "tcp", "example.org:443"); !errors.Is(e, ft.ErrCapacity) {
		t.Fatal("pending dial did not reserve capacity", e)
	}
	if got := client.Snapshot().Transport.Operations.Rejections.SDKCapacity; got != 1 {
		t.Fatal("pending SDK capacity rejection was not recorded", got)
	}
	client.Close()
	select {
	case e := <-result:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatal("pending result", e)
		}
	case <-time.After(time.Second):
		t.Fatal("pending dial retained")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("request not cancelled")
	}
}

func TestPublicSOCKSTransportResetIsNotEOF(t *testing.T) {
	client, _ := endpoint(t, "h2-connect", false, 0)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	reset := make(chan struct{}, 1)
	defer close(reset)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err = conn.Write([]byte("partial")); err != nil {
			return
		}
		select {
		case <-reset:
		case <-time.After(4 * time.Second):
		}
		_ = conn.(*net.TCPConn).SetLinger(0)
	}()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- client.ServeSOCKS(listener) }()
	t.Cleanup(func() {
		client.Close()
		listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("SOCKS supervision did not stop")
		}
	})
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var greeting [2]byte
	if _, err = io.ReadFull(conn, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatal("SOCKS greeting", err)
	}
	port := target.Addr().(*net.TCPAddr).Port
	if _, err = conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, byte(port >> 8), byte(port)}); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil || reply[1] != 0 {
		t.Fatal("SOCKS setup", err, reply)
	}
	var prefix [7]byte
	if _, err = io.ReadFull(conn, prefix[:]); err != nil || string(prefix[:]) != "partial" {
		t.Fatal("partial response", err, string(prefix[:]))
	}
	reset <- struct{}{}
	var next [1]byte
	if _, err = conn.Read(next[:]); err == nil || errors.Is(err, io.EOF) {
		t.Fatal("public SOCKS adapter disguised reset as EOF", err)
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("public SOCKS adapter stalled after reset", err)
	}
}

func TestServerCascadeAPIValidation(t *testing.T) {
	for _, tc := range []struct {
		proxy, dns string
		valid      bool
	}{
		{"socks5://127.0.0.1:1080", "", true},
		{"socks5://127.0.0.1:1080", "9.9.9.9:53", true},
		{"http://127.0.0.1:1080", "", false},
		{"socks5://proxy.example:1080", "", false},
		{"", "9.9.9.9:53", false},
	} {
		_, err := ft.NewServer(ft.ServerConfig{Credentials: ft.Credentials{Username: "alice", Password: "secret"}, EgressProxy: tc.proxy, EgressDNS: tc.dns})
		if (err == nil) != tc.valid {
			t.Fatalf("valid=%v error=%v", tc.valid, err)
		}
	}
}
