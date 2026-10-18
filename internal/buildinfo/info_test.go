package buildinfo

import "testing"

func TestDefaultTLSBackendMatchesCompiledCapabilities(t *testing.T) {
	info := Current()
	want := "go"
	if NSSAvailable {
		want = "nss"
	}
	if info.DefaultTLSBackend != want {
		t.Fatalf("default TLS backend = %q, want %q", info.DefaultTLSBackend, want)
	}
	if len(info.TLSBackends) == 0 || info.TLSBackends[0] != "go" {
		t.Fatalf("Go diagnostic backend unavailable: %v", info.TLSBackends)
	}
	if NSSAvailable && (len(info.TLSBackends) != 2 || info.TLSBackends[1] != "nss") {
		t.Fatalf("tagged NSS build has wrong backend list: %v", info.TLSBackends)
	}
}
