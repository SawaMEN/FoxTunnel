package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/access"
	"github.com/SawaMEN/FoxTunnel/internal/bond"
)

const accessAlice = "alice-random-test-credential-0123456789"
const accessBob = "bob-random-test-credential-9876543210"

func accessPolicy() access.Document {
	return access.Document{Version: 1, Users: []access.User{{ID: "a", Username: "alice", Password: accessAlice}, {ID: "b", Username: "bob", Password: accessBob}}}
}
func accessController(t *testing.T) *access.Controller {
	t.Helper()
	c, err := access.New(accessPolicy(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func accessClient(t *testing.T, c *Client, name, pass, mode string, backend ...string) {
	t.Helper()
	c.Username = name
	c.Password = pass
	selected := "go"
	if len(backend) > 0 {
		selected = backend[0]
	}
	if err := c.SetTLSBackend(selected); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTransport(mode); err != nil {
		t.Fatal(err)
	}
}
func accessEcho(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	p := []byte("account-owned echo")
	if _, err := c.Write(p); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(p))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, p) {
		t.Fatal("echo", got, err)
	}
}
func waitAccess(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("access state did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestAccessRevocationIsolationAllTransports(t *testing.T) {
	testAccessRevocationIsolationAllTransports(t, "go")
}
func testAccessRevocationIsolationAllTransports(t *testing.T, backend string) {
	for _, mode := range []string{"h2-connect", "h2-post", "h3-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "h3-post" && backend == "nss" {
				t.Skip("Go H3 uses its own TLS; Neqo has a separate opt-in")
			}
			ctrl := accessController(t)
			s := &Server{Access: ctrl, AllowPrivate: true, Padding: true}
			alice, addr := testClient(t, s)
			if mode == "h3-post" {
				endpoint := setupEndpoint(t, alice, s)
				startNativeH3(t, endpoint, s)
				usePrimary(t, alice, endpoint.URL)
			}
			accessClient(t, alice, "alice", accessAlice, mode, backend)
			bob, err := NewClient(alice.ServerURL.String(), "bob", accessBob, alice.CACertFile)
			if err != nil {
				t.Fatal(err)
			}
			defer bob.Close()
			accessClient(t, bob, "bob", accessBob, mode, backend)
			target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
			a, code := connectSOCKS(t, addr, target)
			if code != 0 {
				t.Fatal("Alice SOCKS setup", code)
			}
			defer a.Close()
			accessEcho(t, a)
			b, err := bob.DialContext(context.Background(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			accessEcho(t, b)
			// Inner HTTP/2 must be bound to its authenticated outer owner.
			if mode == "wss" || strings.HasPrefix(mode, "xhttp-") {
				r, _ := http.NewRequest("CONNECT", alice.ServerURL.String(), nil)
				r.Host = target
				r.Header.Set("Proxy-Authorization", basicAuth("bob", accessBob))
				resp, err := alice.transport.RoundTrip(r)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != 404 {
					t.Fatal("cross-user inner request accepted", resp.StatusCode)
				}
			}
			d := accessPolicy()
			d.Users[0].Disabled = true
			if err := ctrl.Replace(d); err != nil {
				t.Fatal(err)
			}
			_ = a.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := a.Read(make([]byte, 1)); err == nil {
				t.Fatal("revoked stream still open")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("revocation did not close stream")
			}
			accessEcho(t, b)
			if stats := ctrl.Snapshot(); stats.Users[1].Bytes == 0 {
				t.Fatal("Bob payload not metered", stats)
			}
			waitAccess(t, func() bool { return ctrl.Snapshot().Users[0].ActiveTunnels == 0 })
		})
	}
}
func TestAccessTunnelLimitAndCoverRedaction(t *testing.T) {
	ctrl := accessController(t)
	d := accessPolicy()
	d.Users[0].MaxTunnels = 1
	ctrl.Replace(d)
	var leaked bool
	s := &Server{Access: ctrl, AllowPrivate: true, Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Proxy-Authorization") != ""
		w.WriteHeader(404)
	})}
	bad := httptest.NewRequest("CONNECT", "https://example.org:443", nil)
	bad.ProtoMajor = 2
	bad.Header.Set("Proxy-Authorization", basicAuth("alice", accessAlice+"wrong"))
	s.ServeHTTP(httptest.NewRecorder(), bad)
	if leaked {
		t.Fatal("credentials reached cover")
	}
	c, _ := testClient(t, s)
	accessClient(t, c, "alice", accessAlice, "h2-connect")
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	a, err := c.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if b, err := c.DialContext(context.Background(), "tcp", target); err == nil {
		b.Close()
		t.Fatal("per-user destination limit bypassed")
	}
	a.Close()
	waitAccess(t, func() bool { return ctrl.Snapshot().Users[0].ActiveTunnels == 0 })
	b, err := c.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal("slot not released", err)
	}
	b.Close()
}
func TestAccessBondOwnerAndUniquePayloadAccounting(t *testing.T) {
	ctrl := accessController(t)
	s := &Server{Access: ctrl, AllowPrivate: true}
	hub := s.NewBondHub()
	defer hub.Close()
	s.Bond = hub
	c, _ := testClient(t, s)
	accessClient(t, c, "alice", accessAlice, "h2-connect")
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	var token [32]byte
	binary.BigEndian.PutUint64(token[:8], uint64(time.Now().Unix()))
	_, _ = rand.Read(token[8:])
	var hubID string
	call := func(name, pass string, op byte, payload []byte, lane bool) *http.Response {
		t.Helper()
		body := make([]byte, 49)
		body[0] = op
		copy(body[1:33], token[:])
		body = append(body, payload...)
		if lane {
			body = token[:]
		}
		req, _ := http.NewRequest("POST", c.ServerURL.String()+bond.Path, bytes.NewReader(body))
		req.Header.Set("Proxy-Authorization", basicAuth(name, pass))
		if hubID != "" {
			req.Header.Set("X-FoxTunnel-Bond-Hub", hubID)
		}
		if lane {
			req.Header.Set(bond.LaneHeader, bond.LaneVersion)
		}
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	open := call("alice", accessAlice, 0, []byte(target), false)
	identity, _ := io.ReadAll(open.Body)
	open.Body.Close()
	if open.StatusCode != 200 || len(identity) != 32 {
		t.Fatal("open", open.StatusCode)
	}
	hubID = fmtHex(identity)
	for _, lane := range []bool{false, true} {
		r := call("bob", accessBob, 2, nil, lane)
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != 409 {
			t.Fatal("Bob attached to Alice session", r.StatusCode)
		}
	}
	for range 2 {
		w := call("alice", accessAlice, 1, []byte("abc"), false)
		w.Body.Close()
		if w.StatusCode != 200 {
			t.Fatal("write", w.StatusCode)
		}
	}
	for range 2 {
		r := call("alice", accessAlice, 2, nil, false)
		got, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || string(got) != "abc" {
			t.Fatal("read", r.StatusCode, string(got))
		}
	}
	if got := ctrl.Snapshot().Users[0].Bytes; got != 6 {
		t.Fatal("bond retries double-counted payload", got)
	}
	d := accessPolicy()
	d.Users[0].Disabled = true
	ctrl.Replace(d)
	waitAccess(t, func() bool { return ctrl.Snapshot().Users[0].ActiveTunnels == 0 })
}
func fmtHex(b []byte) string {
	const h = "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, v := range b {
		s[2*i] = h[v>>4]
		s[2*i+1] = h[v&15]
	}
	return string(s)
}

func TestAccessQuotaStopsOnlyExhaustedUser(t *testing.T) {
	ctrl := accessController(t)
	d := accessPolicy()
	d.Users[0].QuotaBytes = 64 << 10
	ctrl.Replace(d)
	server := &Server{Access: ctrl, AllowPrivate: true}
	alice, _ := testClient(t, server)
	accessClient(t, alice, "alice", accessAlice, "h2-connect")
	target := testDestination(t, func(c net.Conn) { _, _ = c.Write(make([]byte, 512<<10)) })
	a, err := alice.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.SetDeadline(time.Now().Add(2 * time.Second))
	received, _ := io.ReadAll(a)
	if len(received) > 64<<10 {
		t.Fatal("quota leaked payload", len(received))
	}
	waitAccess(t, func() bool { return ctrl.Snapshot().Users[0].ActiveTunnels == 0 })
	if n := ctrl.Snapshot().Users[0].Bytes; n > 64<<10 || n == 0 {
		t.Fatal("quota accounting", n)
	}
	bob, err := NewClient(alice.ServerURL.String(), "bob", accessBob, alice.CACertFile)
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Close()
	accessClient(t, bob, "bob", accessBob, "h2-connect")
	echo := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	b, err := bob.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	accessEcho(t, b)
}
