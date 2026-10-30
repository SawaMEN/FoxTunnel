package androidsdk

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestInvalidProfileIsRejected(t *testing.T) {
	if _, err := NewSession("vetroff://bad-profile"); err == nil {
		t.Fatal("invalid link was accepted")
	}
}

func TestStopIsIdempotent(t *testing.T) {
	s := &Session{}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartSOCKS(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("stopped session started SOCKS: %v", err)
	}
	if err := s.NotifyNetworkChange(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("stopped session notification: %v", err)
	}
}

func TestEmptySessionDoesNotExposeCredentials(t *testing.T) {
	s := &Session{}
	if s.StatusJSON() != "{}" {
		t.Fatal("unexpected empty status")
	}
	if strings.Contains(s.LastError(), "vetroff://") {
		t.Fatal("last error contains a profile")
	}
}
