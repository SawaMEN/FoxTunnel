package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SawaMEN/VetroffProxy/internal/bootstrap"
	"github.com/SawaMEN/VetroffProxy/internal/buildinfo"
	"github.com/SawaMEN/VetroffProxy/internal/profile"
)

func checkServerFixture(t *testing.T) (bootstrap.ServerConfig, string) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("offline validation made an HTTP request")
	}))
	t.Cleanup(s.Close)
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	der, err := x509.MarshalPKCS8PrivateKey(s.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}),
		key:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// This port is already occupied: check-config must never bind it.
	c := bootstrap.ServerConfig{Version: 1, Listen: s.Listener.Addr().String(), Certificate: cert, PrivateKey: key, Username: "private-user-marker", Password: "private-password-marker", MaxTunnels: 256, MaxConnections: 512}
	return c, filepath.Join(dir, "server.json")
}

func saveCheckServer(t *testing.T, path string, c bootstrap.ServerConfig) {
	t.Helper()
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func runConfigReport(t *testing.T, args ...string) (configReport, error, string) {
	t.Helper()
	var out bytes.Buffer
	err := checkConfigCommand(append(args, "--json"), &out)
	var report configReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatalf("missing JSON report: %v, command error: %v", e, err)
	}
	return report, err, out.String()
}

func TestCheckConfigServerOfflineAndRedacted(t *testing.T) {
	c, path := checkServerFixture(t)
	saveCheckServer(t, path, c)
	before, _ := os.ReadFile(path)
	r, err, output := runConfigReport(t, "--config", path)
	if err != nil || !r.OK || r.Role != "server" || r.Schema != 1 || len(r.Checks) != 3 || r.Settings["max_tunnels"] != float64(256) {
		t.Fatalf("invalid report: %+v, %v", r, err)
	}
	for _, secret := range []string{c.Username, c.Password, path, c.PrivateKey, c.Certificate, c.Listen} {
		if strings.Contains(output, secret) {
			t.Fatal("report disclosed private configuration")
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("validation modified configuration")
	}
}

func TestCheckConfigServerFailures(t *testing.T) {
	base, path := checkServerFixture(t)
	for _, test := range []struct {
		name string
		edit func(*bootstrap.ServerConfig)
		code string
	}{
		{"missing-key", func(c *bootstrap.ServerConfig) { c.PrivateKey += "-missing" }, "certificate"},
		{"invalid-limit", func(c *bootstrap.ServerConfig) { c.MaxConnections = 0 }, "server_config"},
		{"invalid-port", func(c *bootstrap.ServerConfig) { c.Listen = "127.0.0.1:65536" }, "listen"},
		{"service-port", func(c *bootstrap.ServerConfig) { c.H3Listen = "127.0.0.1:https" }, "listen"},
		{"negative-port", func(c *bootstrap.ServerConfig) { c.Listen = "127.0.0.1:-1" }, "listen"},
		{"cover-overlap", func(c *bootstrap.ServerConfig) { c.WebRoot = filepath.Dir(path) }, "web_root"},
		{"missing-cluster", func(c *bootstrap.ServerConfig) { c.BondHub = true; c.ClusterFile = path + ".cluster" }, "cluster"},
		{"missing-relay-ca", func(c *bootstrap.ServerConfig) {
			c.BondUpstream = "https://unresolvable.invalid"
			c.BondCA = path + ".missing-ca"
		}, "relay"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := base
			test.edit(&c)
			saveCheckServer(t, path, c)
			r, err, output := runConfigReport(t, "--config", path)
			if err == nil || r.OK || r.Settings != nil {
				t.Fatal("invalid server configuration passed")
			}
			found := false
			for _, check := range r.Checks {
				found = found || check.Code == test.code && !check.OK
			}
			if !found || strings.Contains(output, c.Password) || strings.Contains(output, path) {
				t.Fatal("missing expected failure or unredacted output")
			}
		})
	}
}

func TestCheckConfigRejectsUnknownAndDuplicateFields(t *testing.T) {
	c, path := checkServerFixture(t)
	data, _ := json.Marshal(c)
	for _, field := range []string{`"secret-unknown-field":"private-password-marker",`, `"listen":"127.0.0.1:0",`} {
		if err := os.WriteFile(path, append([]byte("{"+field), data[1:]...), 0600); err != nil {
			t.Fatal(err)
		}
		r, err, output := runConfigReport(t, "--config", path)
		if err == nil || r.OK || strings.Contains(output, "secret-unknown-field") || strings.Contains(output, c.Password) {
			t.Fatal("invalid JSON accepted or input echoed")
		}
	}
}

func TestCheckConfigManagedUsersDoesNotCreateLedger(t *testing.T) {
	c, path := checkServerFixture(t)
	c.Username, c.Password = "", ""
	c.UsersFile, c.UsersState = path+".users", path+".ledger"
	policy := []byte(`{"v":1,"users":[{"id":"test","username":"private-user-marker","password":"private-password-marker-012345","quota_bytes":1000}]}`)
	if err := os.WriteFile(c.UsersFile, policy, 0600); err != nil {
		t.Fatal(err)
	}
	saveCheckServer(t, path, c)
	r, err, _ := runConfigReport(t, "--config", path)
	if err != nil || !r.OK {
		t.Fatalf("managed users rejected: %+v, %v", r, err)
	}
	for _, name := range []string{c.UsersState, c.UsersState + ".lock"} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			t.Fatal("validation created ledger or acquired persistent lock")
		}
	}
	if err := os.WriteFile(c.UsersState, []byte(`{"v":1,"charged_bytes":{"test":-1}}`), 0600); err != nil {
		t.Fatal(err)
	}
	r, err, _ = runConfigReport(t, "--config", path)
	if err == nil || r.OK {
		t.Fatal("corrupt ledger accepted")
	}
	if err := os.Remove(c.UsersState); err != nil {
		t.Fatal(err)
	}
	c.BondUpstream = "https://unresolvable.invalid"
	saveCheckServer(t, path, c)
	r, err, _ = runConfigReport(t, "--config", path)
	if err == nil || r.OK {
		t.Fatal("unsupported relay quotas accepted")
	}
}

func TestCheckConfigExpiredAndMismatchedCertificates(t *testing.T) {
	c, path := checkServerFixture(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	bad := c
	bad.PrivateKey = path + ".other-key"
	if err := os.WriteFile(bad.PrivateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}), 0600); err != nil {
		t.Fatal(err)
	}
	saveCheckServer(t, path, bad)
	if r, err, _ := runConfigReport(t, "--config", path); err == nil || r.OK {
		t.Fatal("mismatched certificate/key accepted")
	}
	certPEM, _ := os.ReadFile(c.Certificate)
	keyPEM, _ := os.ReadFile(c.PrivateKey)
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	leaf, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotBefore, leaf.NotAfter = time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.Certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	saveCheckServer(t, path, c)
	if r, err, _ := runConfigReport(t, "--config", path); err == nil || r.OK {
		t.Fatal("expired certificate accepted")
	}
}

func TestCheckConfigClientProfiles(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h2-post", "h3-post", "wss", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "connection.txt")
			link, err := profile.Encode(profile.Config{Version: 1, Servers: []string{"https://unresolvable.invalid"}, Username: "private-user-marker", Password: "private-password-marker", Transport: mode, TLSBackend: "go"})
			if err != nil {
				t.Fatal(err)
			}
			if err := profile.WriteSecretFile(path, link); err != nil {
				t.Fatal(err)
			}
			r, err, output := runConfigReport(t, "--link-file", path)
			if err != nil || !r.OK || r.Role != "client" || r.Settings["transport"] != mode {
				t.Fatalf("profile rejected: %+v, %v", r, err)
			}
			for _, secret := range []string{link, "private-password-marker", "private-user-marker", "unresolvable.invalid", path} {
				if strings.Contains(output, secret) {
					t.Fatal("profile details disclosed")
				}
			}
			_, err, _ = runConfigReport(t, "--link-file", path, "--ca-cert", path+".missing")
			if err == nil {
				t.Fatal("missing CA accepted")
			}
		})
	}
}

func TestCheckConfigUnavailableNSS(t *testing.T) {
	if buildinfo.NSSAvailable {
		t.Skip("requires build without NSS")
	}
	path := filepath.Join(t.TempDir(), "connection.txt")
	link, err := profile.Encode(profile.Config{Version: 1, Servers: []string{"https://unresolvable.invalid"}, Username: "test", Password: "secret", TLSBackend: "nss"})
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.WriteSecretFile(path, link); err != nil {
		t.Fatal(err)
	}
	for _, options := range [][]string{{}, {"--engine", "mozilla"}} {
		r, err, _ := runConfigReport(t, append([]string{"--link-file", path}, options...)...)
		if err == nil || r.OK {
			t.Fatal("unavailable native backend accepted")
		}
	}
}

func TestCheckConfigArgumentsAndExitStatus(t *testing.T) {
	for _, args := range [][]string{nil, {"--config", "a", "--link-file", "b"}, {"--link-file", "-"}, {"--config", "a", "--engine", "builtin"}, {"--config", "a", "extra"}, {"--json=private-password-marker"}} {
		var out bytes.Buffer
		err := checkConfigCommand(args, &out)
		if err == nil || strings.Contains(err.Error()+out.String(), "private-password-marker") {
			t.Fatal("bad arguments accepted or echoed")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "check-config", "--config", "private-path-marker", "--json")
	cmd.Env = helperEnv(false)
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), `"ok":false`) || strings.Contains(string(output), "private-path-marker") {
		t.Fatal("CLI must fail without disclosing input")
	}
	cmd = helperCommand(ctx, "check-config", "--help")
	cmd.Env = helperEnv(false)
	if output, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(output), "--link-file") {
		t.Fatal("CLI help failed")
	}
}
