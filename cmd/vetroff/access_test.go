package main

import (
	"context"
	"encoding/json"
	"github.com/SawaMEN/VetroffProxy/internal/access"
	"github.com/SawaMEN/VetroffProxy/internal/bootstrap"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const cliSecret = "random-cli-test-secret-0123456789012345"

func cliPolicyFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "users.json")
	data, _ := json.Marshal(access.Document{Version: 1, Users: []access.User{{ID: "operator-id", Username: "private-username", Password: cliSecret, QuotaBytes: 123456}}})
	if os.WriteFile(p, data, 0600) != nil {
		t.Fatal("fixture")
	}
	return p
}
func TestAccessCommandRedactsAndRejectsSecretInput(t *testing.T) {
	file := cliPolicyFile(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := helperCommand(ctx, "access", "--users-file", file)
	cmd.Env = helperEnv(false)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err, string(out))
	}
	if !strings.Contains(string(out), "operator-id") || strings.Contains(string(out), cliSecret) || strings.Contains(string(out), "private-username") {
		t.Fatal("unsafe offline diagnostics", string(out))
	}
	os.WriteFile(file, []byte(`{"v":1,"users":[],"password":"`+cliSecret+`"}`), 0600)
	cmd = helperCommand(ctx, "access", "--users-file", file)
	cmd.Env = helperEnv(false)
	out, err = cmd.CombinedOutput()
	if err == nil || strings.Contains(string(out), cliSecret) {
		t.Fatal("secret appeared in parse error", string(out))
	}
}
func TestAccessPathsCannotOverwritePolicy(t *testing.T) {
	p := cliPolicyFile(t)
	data, _ := os.ReadFile(p)
	if checkAccessPaths(p, p) == nil {
		t.Fatal("same file accepted")
	}
	other := filepath.Join(filepath.Dir(p), "other.json")
	if os.Link(p, other) != nil {
		t.Fatal("hardlink fixture")
	}
	if checkAccessPaths(p, other) == nil {
		t.Fatal("hardlinked file accepted")
	}
	after, _ := os.ReadFile(p)
	if string(data) != string(after) {
		t.Fatal("policy overwritten")
	}
}
func TestManagedServerConfigAndRelayQuotaRejection(t *testing.T) {
	file := cliPolicyFile(t)
	path := filepath.Join(filepath.Dir(file), "server.json")
	config := bootstrap.ServerConfig{Version: 1, Listen: "127.0.0.1:8443", Certificate: "cert.pem", PrivateKey: "key.pem", UsersFile: file, UsersState: filepath.Join(filepath.Dir(file), "usage.json"), MaxConnections: 512, MaxTunnels: 256}
	data, _ := json.Marshal(config)
	os.WriteFile(path, data, 0600)
	if _, err := bootstrap.ReadServer(path); err != nil {
		t.Fatal(err)
	}
	config.Username = "builtin"
	config.Password = "builtin"
	data, _ = json.Marshal(config)
	os.WriteFile(path, data, 0600)
	if _, err := bootstrap.ReadServer(path); err == nil {
		t.Fatal("managed/builtin mixture accepted")
	}
	if _, err := readAccessPolicy(file, true); err == nil {
		t.Fatal("exit payload quota silently accepted on a relay")
	}
}
