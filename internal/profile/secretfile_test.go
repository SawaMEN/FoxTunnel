package profile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSecretLinkFilePrivacyAndNoOverwrite(t *testing.T) {
	link, err := Encode(Config{Version: 1, Servers: []string{"https://example.org"}, Username: "user", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.link")
	if err := WriteSecretFile(path, link); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("not private: %o", info.Mode().Perm())
	}
	decoded, err := ReadSecretFile(path)
	if err != nil || decoded.Username != "user" || decoded.Password != "secret" {
		t.Fatalf("secret link not imported: %v", err)
	}
	if err := WriteSecretFile(path, link); err == nil {
		t.Fatal("overwrote an existing connection secret")
	}
	if err := WriteSecretFile(filepath.Join(t.TempDir(), "link"), "vetroff://bad"); err == nil {
		t.Fatal("wrote an invalid link")
	}
}

func TestSecretLinkFileRejectsWorldAccessAndSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes and symlinks")
	}
	link, err := Encode(Config{Version: 1, Servers: []string{"https://example.org"}, Username: "user", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.link")
	if err := os.WriteFile(path, []byte(link+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretFile(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world readable secrets accepted: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	sym := filepath.Join(dir, "symlink.link")
	if err := os.Symlink(path, sym); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretFile(sym); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := WriteSecretFile(sym, link); err == nil {
		t.Fatal("symlink followed on private output")
	}
}
