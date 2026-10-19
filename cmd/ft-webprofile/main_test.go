package main

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"github.com/SawaMEN/FoxTunnel/internal/webprofile"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestPageScenarioUsesVerifiedH2WithoutTunnel(t *testing.T) {
	var called atomic.Bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		if r.Method != "GET" || r.URL.Path != "/" || r.ProtoMajor != 2 || r.TLS.Version != tls.VersionTLS13 || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("unexpected page request")
		}
		w.Write([]byte("Controlled HTTPS fixture."))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	if e := samplePage(server.URL, ca, "go", "firefox-158", ""); e != nil {
		t.Fatal(e)
	}
	if !called.Load() {
		t.Fatal("page never requested")
	}
}
func TestComparisonCLIProducesReportEvenWhenStrictFails(t *testing.T) {
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	out := filepath.Join(t.TempDir(), "comparison.json")
	os.Args = []string{"ft-webprofile", "--input", "../../docs/measurements/2026-10-18/foxtunnel-nss-3.130-xhttp.json", "--compare", "../../docs/measurements/2026-10-18/firefox-158-linux.json", "--comparison-out", out, "--out", filepath.Join(t.TempDir(), "profile.json"), "--strict"}
	if e := run(); e == nil {
		t.Fatal("strict comparison hid differences")
	}
	data, e := os.ReadFile(out)
	if e != nil {
		t.Fatal(e)
	}
	var result webprofile.Comparison
	if e = json.Unmarshal(data, &result); e != nil {
		t.Fatal(e)
	}
	if result.InitialMetadataEqual || len(result.Checks) < 15 {
		t.Fatal("incomplete comparison report")
	}
}
