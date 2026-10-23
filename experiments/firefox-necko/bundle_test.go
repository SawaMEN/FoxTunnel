package firefox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testBundle(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	m := bundleManifest{Schema: 1, HelperProtocol: BundleProtocol, Platform: "linux-amd64", SourceLockSHA256: digestBytes(sourceLock), ClientJSSHA256: digestBytes(clientScript), Files: map[string]string{}}
	for _, name := range []string{"runtime/xpcshell", "runtime/libxul.so", "runtime/libnss3.so", "runtime/platform.ini", "provenance.json", "source-lock.json", "foxtunnel-necko"} {
		data := []byte("fixture " + name)
		os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700)
		if e := os.WriteFile(filepath.Join(root, name), data, 0600); e != nil {
			t.Fatal(e)
		}
		m.Files[name] = digestBytes(data)
	}
	data, _ := json.Marshal(m)
	if e := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	return root
}
func TestBundleRejectsCorruptionLinksAndIncompatibleHelper(t *testing.T) {
	root := testBundle(t)
	if _, e := verifyBundle(root); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"runtime/xpcshell", "runtime/libxul.so", "source-lock.json"} {
		t.Run(name, func(t *testing.T) {
			root := testBundle(t)
			os.WriteFile(filepath.Join(root, name), []byte("tampered"), 0600)
			if _, e := verifyBundle(root); e == nil {
				t.Fatal("accepted tampered bundle")
			}
		})
	}
	for _, kind := range []string{"extra-file", "extra-link", "replacement-link", "missing", "helper-version", "helper-js", "source-lock"} {
		t.Run(kind, func(t *testing.T) {
			root := testBundle(t)
			switch kind {
			case "extra-file":
				os.WriteFile(filepath.Join(root, "runtime/injected.so"), nil, 0600)
			case "extra-link":
				os.Symlink("/etc", filepath.Join(root, "runtime/outside"))
			case "replacement-link":
				os.Remove(filepath.Join(root, "runtime/xpcshell"))
				os.Symlink("/bin/true", filepath.Join(root, "runtime/xpcshell"))
			case "missing":
				os.Remove(filepath.Join(root, "runtime/libxul.so"))
			default:
				var m bundleManifest
				data, _ := os.ReadFile(filepath.Join(root, "manifest.json"))
				json.Unmarshal(data, &m)
				if kind == "helper-version" {
					m.HelperProtocol++
				}
				if kind == "helper-js" {
					m.ClientJSSHA256 = "wrong"
				}
				if kind == "source-lock" {
					m.SourceLockSHA256 = "wrong"
				}
				data, _ = json.Marshal(m)
				os.WriteFile(filepath.Join(root, "manifest.json"), data, 0600)
			}
			if _, e := verifyBundle(root); e == nil {
				t.Fatal("accepted incompatible bundle")
			}
		})
	}
}
func TestLifetimeConfigValidation(t *testing.T) {
	base := Config{Server: "https://example.invalid", Username: "u", Password: "p", MaxConnections: 8}
	for _, mutate := range []func(*Config){func(c *Config) { c.IdleTimeoutMS = 1 }, func(c *Config) { c.DrainTimeoutMS = -1 }, func(c *Config) { c.MaxRetainedConnections = 7 }, func(c *Config) { c.StatsIntervalMS = 1 }} {
		c := base
		mutate(&c)
		if _, e := c.normalize(); e == nil {
			t.Fatal("accepted unbounded/invalid lifetime config")
		}
	}
}

func TestBundleResolvesVersionPointerBeforeExecution(t *testing.T) {
	first := testBundle(t)
	second := testBundle(t)
	pointer := filepath.Join(t.TempDir(), "current")
	if e := os.Symlink(first, pointer); e != nil {
		t.Fatal(e)
	}
	verified, e := verifyBundle(pointer)
	if e != nil {
		t.Fatal(e)
	}
	os.Remove(pointer)
	if e := os.Symlink(second, pointer); e != nil {
		t.Fatal(e)
	}
	if verified != filepath.Join(first, "runtime", "xpcshell") {
		t.Fatal("verified runtime still follows mutable version pointer")
	}
}

func TestBundleExecutionPlatformGate(t *testing.T) {
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		return
	}
	if _, err := VerifyBundle(testBundle(t)); err == nil {
		t.Fatal("unsupported host accepted executable bundle")
	}
}
