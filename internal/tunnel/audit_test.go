package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAuditFallbackRejectsPortAliases(t *testing.T) {
	c, err := NewClient("https://node.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetFallbackServers([]string{"https://NODE.example:0443"}); err == nil {
		t.Fatal("same endpoint admitted twice via port spelling")
	}
}

func TestAuditPinsMatchEquivalentOrigin(t *testing.T) {
	c, err := NewClient("https://node.example:443", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	file := filepath.Join(t.TempDir(), "pins.json")
	data := []byte(`{"v":1,"nodes":[{"url":"https://NODE.example","pin_sha256":"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}`)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.SetNodePinsFile(file); err != nil {
		t.Fatal("equivalent default-port origin refused by pins:", err)
	}
}

func TestAuditPinnedClientRejectsFallbackReconfiguration(t *testing.T) {
	c, err := NewClient("https://node.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	file := filepath.Join(t.TempDir(), "pins.json")
	data := []byte(`{"v":1,"nodes":[{"url":"https://node.example","pin_sha256":"sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}`)
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.SetNodePinsFile(file); err != nil {
		t.Fatal(err)
	}
	if err := c.SetFallbackServers([]string{"https://unreviewed.example"}); err == nil {
		t.Fatal("new fallback bypassed mandatory SPKI policy")
	}
}

func TestAuditClientRejectsUnusableCredentials(t *testing.T) {
	for _, pair := range [][2]string{{strings.Repeat("u", 257), "p"}, {"alice", strings.Repeat("p", 1025)}, {"a\nb", "p"}} {
		c, err := NewClient("https://node.example", pair[0], pair[1], "")
		if c != nil {
			c.Close()
		}
		if err == nil {
			t.Fatal("client accepted credentials the wire parser cannot accept")
		}
	}
}

type auditTransport struct{ called bool }

func (a *auditTransport) CloseIdleConnections() {}
func (a *auditTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	a.called = true
	return &http.Response{StatusCode: 200, ProtoMajor: 2, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
}
func TestAuditCancelledDialNeverStartsTransport(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	c, err := NewClient("https://node.example", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	transport := &auditTransport{}
	c.transport = transport
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := c.DialContext(ctx, "tcp", "example.org:443")
	if conn != nil {
		conn.Close()
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if transport.called {
		t.Fatal("already-cancelled dial reached request transport")
	}
}

func TestAuditUTF8CredentialsTransferOverH2(t *testing.T) {
	target := testDestination(t, func(c net.Conn) { _, _ = io.Copy(c, c) })
	c, addr := testClient(t, &Server{Username: "пользователь", Password: "secret", AllowPrivate: true})
	c.Username = "пользователь"
	conn, code := connectSOCKS(t, addr, target)
	if code != 0 {
		t.Fatal("UTF-8 profile rejected by server", code)
	}
	if _, err := conn.Write([]byte("utf8")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "utf8" {
		t.Fatal("UTF-8 authenticated transfer", err)
	}
}
