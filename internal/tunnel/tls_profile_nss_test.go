//go:build nss && cgo && linux

package tunnel

import (
	"github.com/SawaMEN/FoxTunnel/internal/nsstls"
	"testing"
)

func requireMozillaRuntime(t *testing.T) {
	t.Helper()
	if nsstls.Version() != "3.130" {
		t.Skip("requires pinned NSS runtime")
	}
}
func TestNSSMozillaClientProfileTransports(t *testing.T) {
	requireMozillaRuntime(t)
	testNativeTransports(t, "nss", nsstls.Firefox158)
}
func TestNSSMozillaClientProfileTLSRejection(t *testing.T) {
	requireMozillaRuntime(t)
	testNativeVerificationBeforeCredentials(t, "nss", "", nsstls.Firefox158)
}
func TestNSSMozillaClientProfileWireAndCredit(t *testing.T) {
	requireMozillaRuntime(t)
	testHTTP2ReceiveProfile(t, "nss", nsstls.Firefox158)
	testHTTP2ReceiveProfileCreditRenewal(t, "nss", nsstls.Firefox158)
}
func TestNSSMozillaClientProfileTransitions(t *testing.T) {
	requireMozillaRuntime(t)
	c, e := NewClient("https://example.org", "alice", "secret", "")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if e = c.SetTLSClientProfile(nsstls.Firefox158); e != nil {
		t.Fatal(e)
	}
	old := c.transport
	if e = c.SetTLSBackend("go"); e == nil || old != c.transport || c.backend != "auto" {
		t.Fatal("incompatible backend transition accepted", e)
	}
	if e = c.SetTransport("h3-post"); e == nil || old != c.transport || c.nativeTransport != "" {
		t.Fatal("incompatible H3 transition accepted", e)
	}
	if e = c.SetServerIdentity("another.example", ""); e != nil {
		t.Fatal(e)
	}
	pool := c.transport.(*identityPool)
	if pool.tlsClientProfile != nsstls.Firefox158 {
		t.Fatal("profile lost on identity rebuild")
	}
	if e = c.SetTLSClientProfile("default"); e != nil || c.tlsClientProfile != "" {
		t.Fatal("cannot reset profile", e)
	}
	if e = c.SetTLSBackend("go"); e != nil {
		t.Fatal(e)
	}
}

func TestNSSMozillaClientProfileCancellation(t *testing.T) {
	requireMozillaRuntime(t)
	testHTTP2ReceiveProfileCancellation(t, "nss", nsstls.Firefox158)
}
