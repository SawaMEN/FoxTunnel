//go:build !nss || !cgo || !linux

package tunnel

import (
	"strings"
	"testing"
)

func TestNSSUnavailableDoesNotSilentlySelectGo(t *testing.T) {
	c, err := NewClient("https://example.org", "alice", "secret", "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SetTLSBackend("nss"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("expected explicit unavailable error: %v", err)
	}
	if err := c.SetTLSBackend("unknown"); err == nil {
		t.Fatal("accepted unknown backend")
	}
}
