package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SawaMEN/FoxTunnel/internal/bootstrap"
	"github.com/SawaMEN/FoxTunnel/internal/profile"
)

func TestSetupCLIAndServerConfig(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer s.Close()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	keyDER, err := x509.MarshalPKCS8PrivateKey(s.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600) != nil || os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600) != nil {
		t.Fatal("fixture write")
	}
	out := filepath.Join(dir, "generated")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	setup := helperCommand(ctx, "setup", "--server", "https://example.com", "--cert", certPath, "--key", keyPath, "--ca-cert", certPath, "--out", out, "--transport", "xhttp-stream-up", "--xhttp-path", "/api/test", "--xhttp-host", "route.example")
	setup.Env = helperEnv(false)
	message, err := setup.CombinedOutput()
	if err != nil {
		t.Fatal("setup CLI failed", err, string(message))
	}
	configFile := filepath.Join(out, "server.json")
	config, err := bootstrap.ReadServer(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if config.XHTTPPath != "/api/test/" || config.XHTTPHost != "route.example" {
		t.Fatal("setup flags were not saved")
	}
	if strings.Contains(string(message), config.Password) || strings.Contains(string(message), "vetroff://") {
		t.Fatal("setup printed secrets")
	}
	config.Listen = "127.0.0.1:0"
	data, _ := json.Marshal(config)
	if err := os.WriteFile(configFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	server := helperCommand(ctx, "server", "--config", configFile)
	server.Env = helperEnv(false)
	stderr, err := server.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	line, err := bufio.NewReader(stderr).ReadString('\n')
	if err != nil || !strings.Contains(line, "HTTPS") || strings.Contains(line, config.Password) {
		t.Fatal("server config did not start", err, line)
	}
	conflict := helperCommand(ctx, "server", "--config", configFile, "--listen", "127.0.0.1:0")
	conflict.Env = helperEnv(false)
	if output, err := conflict.CombinedOutput(); err == nil || strings.Contains(string(output), config.Password) {
		t.Fatal("ambiguous server config accepted")
	}
}

func TestShareSingleCoordinator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "share", "--server", "https://main.example", "--bond", "--discover")
	cmd.Env = helperEnv(true)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	config, err := profile.Decode(strings.TrimSpace(string(out)))
	if err != nil || !config.Discover || !config.Bond || len(config.Servers) != 1 || config.Servers[0] != "https://main.example" {
		t.Fatal("coordinator settings missing from link", err)
	}
}

// main contains exit paths; exercise it in an isolated copy of the test binary.
func TestCLIHelper(t *testing.T) {
	if os.Getenv("FOXTUNNEL_TEST_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"vetroffproxy"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	os.Exit(2)
}
func helperEnv(credentials bool) []string {
	var env []string
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "FOXTUNNEL_USER=") || strings.HasPrefix(value, "FOXTUNNEL_PASSWORD=") || strings.HasPrefix(value, "FOXTUNNEL_SOCKS_") || strings.HasPrefix(value, "FOXTUNNEL_TEST_HELPER=") {
			continue
		}
		env = append(env, value)
	}
	env = append(env, "FOXTUNNEL_TEST_HELPER=1")
	if credentials {
		env = append(env, "FOXTUNNEL_USER=demo-user", "FOXTUNNEL_PASSWORD=example-only-password")
	}
	return env
}
func helperCommand(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestCLIHelper$", "--"}, args...)...)
}
func TestShareAndImportFromStdin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	share := helperCommand(ctx, "share", "--server", "https://a.example", "--fallback-server", "https://b.example", "--bond", "--bond-pipeline", "8")
	share.Env = helperEnv(true)
	output, err := share.Output()
	if err != nil {
		t.Fatal("share failed", err)
	}
	link := strings.TrimSpace(string(output))
	if !strings.HasPrefix(link, "vetroff://") {
		t.Fatal("wrong connection scheme")
	}
	client := helperCommand(ctx, "client", "--link-file", "-", "--listen", "127.0.0.1:0", "--h2-receive-profile", "firefox-158", "--bond-lanes")
	client.Env = helperEnv(false)
	client.Stdin = strings.NewReader(link + "\n")
	stderr, err := client.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { client.Process.Kill(); client.Wait() }()
	line, err := bufio.NewReader(stderr).ReadString('\n')
	if err != nil || !strings.Contains(line, "SOCKS5") || strings.Contains(line, "vetroff://") || strings.Contains(line, "example-only-password") {
		t.Fatal("stdin import did not start a redacted listener", err)
	}
	conflict := helperCommand(ctx, "client", "--link", link, "--server", "https://other.example")
	conflict.Env = helperEnv(false)
	rejected, err := conflict.CombinedOutput()
	if err == nil || strings.Contains(string(rejected), link) || strings.Contains(string(rejected), "example-only-password") {
		t.Fatal("conflicting settings accepted or link disclosed")
	}
}

func TestShareXHTTPRouteCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "share", "--server", "https://main.example", "--transport", "xhttp-stream-up", "--xhttp-path", "/api/custom", "--xhttp-host", "route.example", "--sni", "tls.example")
	cmd.Env = helperEnv(true)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	c, err := profile.Decode(strings.TrimSpace(string(out)))
	if err != nil || c.XHTTPPath != "/api/custom/" || c.XHTTPHost != "route.example" || c.SNI != "tls.example" {
		t.Fatal("CLI route lost", err)
	}
	conflict := helperCommand(ctx, "share", "--link", strings.TrimSpace(string(out)), "--xhttp-path", "/other")
	conflict.Env = helperEnv(false)
	if msg, err := conflict.CombinedOutput(); err == nil || strings.Contains(string(msg), "vetroff://") || strings.Contains(string(msg), "example-only-password") {
		t.Fatal("ambiguous import accepted or leaked credentials")
	}
}

func TestPrivateShareFileAndImportPermissions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "client.link")
	share := helperCommand(ctx, "share", "--server", "https://example.org", "--out", path)
	share.Env = helperEnv(true)
	output, err := share.CombinedOutput()
	if err != nil || strings.Contains(string(output), "vetroff://") || strings.Contains(string(output), "example-only-password") {
		t.Fatalf("share did not keep credentials private: %v %q", err, output)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("share created readable secret file: %o", fi.Mode().Perm())
	}
	// Private files can start clients exactly as --link-file - used to.
	client := helperCommand(ctx, "client", "--link-file", path, "--listen", "127.0.0.1:0")
	client.Env = helperEnv(false)
	stderr, err := client.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stderr).ReadString('\n')
	if err != nil || !strings.Contains(line, "SOCKS5") {
		t.Fatal("private link import did not start client", err, line)
	}
	_ = client.Process.Kill()
	_ = client.Wait()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	reject := helperCommand(ctx, "client", "--link-file", path)
	reject.Env = helperEnv(false)
	out, err := reject.CombinedOutput()
	if err == nil || strings.Contains(string(out), "example-only-password") || strings.Contains(string(out), "vetroff://") {
		t.Fatal("world-readable link file imported or secret leaked")
	}
	again := helperCommand(ctx, "share", "--server", "https://example.org", "--out", path)
	again.Env = helperEnv(true)
	out, err = again.CombinedOutput()
	if err == nil || strings.Contains(string(out), "vetroff://") || strings.Contains(string(out), "example-only-password") {
		t.Fatal("private link share overwrote existing file")
	}
}

func TestSOCKSLocalAndNetworkSafetyCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	base := []string{"client", "--server", "https://example.org", "--listen", "0.0.0.0:0"}
	without := helperCommand(ctx, base...)
	without.Env = helperEnv(true)
	if out, err := without.CombinedOutput(); err == nil || !strings.Contains(string(out), "socks-allow-lan") {
		t.Fatalf("public SOCKS5 without auth/explicit opt-in accepted: %q %v", out, err)
	}
	withAuth := helperCommand(ctx, base...)
	withAuth.Env = append(helperEnv(true), "FOXTUNNEL_SOCKS_USER=local", "FOXTUNNEL_SOCKS_PASSWORD=local-only-password")
	if out, err := withAuth.CombinedOutput(); err == nil || !strings.Contains(string(out), "socks-allow-lan") {
		t.Fatalf("public SOCKS5 without explicit opt-in accepted: %q %v", out, err)
	}
	missing := helperCommand(ctx, "client", "--server", "https://example.org")
	missing.Env = append(helperEnv(true), "FOXTUNNEL_SOCKS_USER=local")
	if out, err := missing.CombinedOutput(); err == nil || !strings.Contains(string(out), "FOXTUNNEL_SOCKS_") {
		t.Fatalf("incomplete SOCKS credentials accepted: %q %v", out, err)
	}
}

func TestVersionMachineContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "version", "--json")
	cmd.Env = helperEnv(true)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Schema   int    `json:"schema"`
		Version  string `json:"version"`
		Flavor   string `json:"build_flavor"`
		Protocol string `json:"protocol_draft"`
	}
	if err = json.Unmarshal(output, &info); err != nil {
		t.Fatal(err)
	}
	if info.Schema != 1 || info.Version == "" || info.Protocol != "foxtunnel-draft-0" || (info.Flavor != "go" && info.Flavor != "nss") {
		t.Fatal("invalid version contract", string(output))
	}
	if strings.Contains(string(output), "example-only-password") {
		t.Fatal("version disclosed credentials")
	}
}

func TestTLSClientProfileWithStdinLinkRejectsGoWithoutDisclosure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	share := helperCommand(ctx, "share", "--server", "https://a.example", "--tls-backend", "go")
	share.Env = helperEnv(true)
	output, e := share.Output()
	if e != nil {
		t.Fatal(e)
	}
	link := strings.TrimSpace(string(output))
	client := helperCommand(ctx, "client", "--link-file", "-", "--tls-client-profile", "firefox-158")
	client.Env = helperEnv(false)
	client.Stdin = strings.NewReader(link + "\n")
	rejected, e := client.CombinedOutput()
	if e == nil || !strings.Contains(string(rejected), "NSS") || strings.Contains(string(rejected), "vetroff://") || strings.Contains(string(rejected), "example-only-password") {
		t.Fatal("profile ignored or credentials disclosed", e)
	}
}

func TestBondLanesRequiresBondAndIsLocal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "client", "--server", "https://example.org", "--bond-lanes")
	cmd.Env = helperEnv(true)
	output, err := cmd.CombinedOutput()
	if err == nil || (!strings.Contains(string(output), "--bond") && !strings.Contains(string(output), "объедин")) {
		t.Fatal("lane flag did not require bond", err, string(output))
	}
	cmd = helperCommand(ctx, "share", "--server", "https://example.org", "--bond-lanes")
	cmd.Env = helperEnv(true)
	if output, err = cmd.CombinedOutput(); err == nil || strings.Contains(string(output), "example-only-password") {
		t.Fatal("local lane option accepted by share or credentials disclosed")
	}
}

func TestQUICOptionsAreLocalAndAcceptImportedH3Link(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	share := helperCommand(ctx, "share", "--server", "https://example.org", "--transport", "h3-post", "--tls-backend", "auto")
	share.Env = helperEnv(true)
	output, err := share.Output()
	if err != nil {
		t.Fatal(err)
	}
	client := helperCommand(ctx, "client", "--link-file", "-", "--quic-backend", "invalid", "--h3-fallback", "h2", "--quic-handshake-timeout", "150ms")
	client.Env = helperEnv(false)
	client.Stdin = strings.NewReader(strings.TrimSpace(string(output)))
	rejected, err := client.CombinedOutput()
	if err == nil || !strings.Contains(string(rejected), "QUIC backend") || strings.Contains(string(rejected), "example-only-password") {
		t.Fatal("local options ignored, rejected as link settings, or secret disclosed", err, string(rejected))
	}
	share = helperCommand(ctx, "share", "--server", "https://example.org", "--quic-backend", "neqo")
	share.Env = helperEnv(true)
	rejected, err = share.CombinedOutput()
	if err == nil || strings.Contains(string(rejected), "example-only-password") {
		t.Fatal("local QUIC option exported or secret disclosed")
	}
}

func TestProtocolCoreCLIContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "version", "--json")
	cmd.Env = helperEnv(false)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Product           string `json:"product"`
		IntegrationSchema int    `json:"integration_schema"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		t.Fatal(err)
	}
	if info.Product != "protocol-core" || info.IntegrationSchema != 1 {
		t.Fatalf("wrong integration identity: %s", out)
	}
	cmd = helperCommand(ctx, "client", "--tun", "ftun0")
	cmd.Env = helperEnv(true)
	out, err = cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "flag provided but not defined") {
		t.Fatalf("system TUN flag accepted: %s (%v)", out, err)
	}
}
