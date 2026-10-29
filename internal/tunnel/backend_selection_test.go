package tunnel

import (
	"testing"

	"github.com/SawaMEN/VetroffProxy/internal/buildinfo"
)

func TestAutoBackendFollowsTransportAndBuild(t *testing.T) {
	c, err := NewClient("https://example.org", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	expected := "go"
	if buildinfo.NSSAvailable {
		expected = "nss"
	}
	check := func(want string) {
		t.Helper()
		pool, ok := c.transport.(*identityPool)
		if !ok || pool.backend != want {
			t.Fatalf("resolved backend = %T %v, want %q", c.transport, pool, want)
		}
		if c.backend != "auto" {
			t.Fatalf("automatic intent lost: %q", c.backend)
		}
	}
	check(expected)
	if err := c.SetTransport("h3-post"); err != nil {
		t.Fatal(err)
	}
	check("go")
	if err := c.SetTransport("wss"); err != nil {
		t.Fatal(err)
	}
	check(expected)
	if err := c.SetTransport("xhttp-stream-one"); err != nil {
		t.Fatal(err)
	}
	check(expected)
	if err := c.SetTLSBackend("go"); err != nil {
		t.Fatal(err)
	}
	if c.backend != "go" || c.transport.(*identityPool).backend != "go" {
		t.Fatal("explicit Go diagnostic backend was not preserved")
	}
	if err := c.SetTransport("h3-post"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTLSBackend("nss"); err == nil {
		t.Fatal("explicit NSS must not silently fall back to Go QUIC for HTTP/3")
	}
	if c.backend != "go" || c.transport.(*identityPool).backend != "go" {
		t.Fatal("failed explicit NSS selection changed the working transport")
	}
}

func TestAutoBackendIsAvailableWithoutNSS(t *testing.T) {
	c, err := NewClient("https://example.org", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetTLSBackend("auto"); err != nil {
		t.Fatal(err)
	}
	if err := c.SetTLSBackend("invalid"); err == nil {
		t.Fatal("unknown TLS backend accepted")
	}
}
