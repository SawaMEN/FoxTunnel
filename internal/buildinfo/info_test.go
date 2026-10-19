package buildinfo

import (
	"github.com/SawaMEN/FoxTunnel/internal/neqo"
	"testing"
)

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

func TestCompiledQUICBackendsAreExplicit(t *testing.T) {
	info := Current()
	if len(info.QUICBackends) == 0 || info.QUICBackends[0] != "quic-go" {
		t.Fatal("default QUIC backend changed")
	}
	if neqo.Available {
		if len(info.QUICBackends) != 2 || info.QUICBackends[1] != "neqo" || info.NeqoVersion != neqo.Version || info.NeqoRevision != neqo.Revision {
			t.Fatal("Neqo metadata missing")
		}
	} else if len(info.QUICBackends) != 1 || info.NeqoVersion != "" {
		t.Fatal("uncompiled Neqo advertised")
	}
}
