package transportengine

import (
	"runtime"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/buildinfo"
	"github.com/SawaMEN/FoxTunnel/internal/neqo"
)

func TestAutoEngineSelection(t *testing.T) {
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		p, err := Resolve(Config{Engine: "auto", NeckoBundle: "/nonexistent/verified-at-apply", Transport: "h3-connect"})
		if err != nil || p.Engine != "necko" || p.Transport != "h3-connect" {
			t.Fatalf("compatible packaged Necko: %+v, %v", p, err)
		}
		p, err = Resolve(Config{Engine: "auto", NeckoBundle: "/nonexistent", Transport: "h2-connect", AutoNeckoExcluded: true})
		if err != nil || p.Engine == "necko" {
			t.Fatalf("unsupported policy selected Necko: %+v %v", p, err)
		}
	}
	p, err := Resolve(Config{Engine: "auto", Transport: "h3-connect", AutoNeckoExcluded: true})
	if err != nil {
		t.Fatal(err)
	}
	expected := "legacy"
	if buildinfo.NSSAvailable && neqo.Available {
		expected = "mozilla"
	}
	if p.Engine != expected || p.Transport != "h3-connect" {
		t.Fatalf("H3 fallback must preserve transport: %+v, expected %s", p, expected)
	}
	p, err = Resolve(Config{Engine: "auto", Transport: "h2-post", TLSBackend: "go", AutoNeckoExcluded: true})
	if err != nil || p.Engine != "legacy" {
		t.Fatalf("explicit Go TLS must not select NSS: %+v %v", p, err)
	}
}

func TestExplicitNeckoNeverDowngrades(t *testing.T) {
	_, err := Resolve(Config{Engine: "necko", Transport: "xhttp-stream-one"})
	if err == nil {
		t.Fatal("explicit necko must reject unsupported transport")
	}
	_, err = Resolve(Config{Engine: "legacy", NeckoBundle: "/tmp/necko"})
	if err == nil {
		t.Fatal("legacy may not accept a Necko bundle")
	}
}
