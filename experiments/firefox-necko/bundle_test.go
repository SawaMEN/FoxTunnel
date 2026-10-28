package firefox

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testBundle(t *testing.T) string {
	return testBundlePlatform(t, "linux-amd64")
}
func testBundlePlatform(t *testing.T, platform string) string {
	t.Helper()
	root := t.TempDir()
	m := bundleManifest{Schema: 1, HelperProtocol: BundleProtocol, Platform: platform, SourceLockSHA256: digestBytes(sourceLock), ClientJSSHA256: digestBytes(clientScript), Files: map[string]string{}}
	for _, name := range []string{"runtime/xpcshell", "runtime/libxul.so", "runtime/libnss3.so", "runtime/platform.ini", "provenance.json", "source-lock.json", "foxtunnel-necko"} {
		data := []byte("fixture " + name)
		if name == "source-lock.json" {
			data = sourceLock
		}
		if name == "runtime/xpcshell" || name == "runtime/libxul.so" || name == "runtime/libnss3.so" || name == "foxtunnel-necko" {
			data = make([]byte, 64)
			copy(data, []byte{127, 'E', 'L', 'F', 2, 1, 1})
			binary.LittleEndian.PutUint16(data[16:18], 3)
			machine := uint16(62)
			if platform == "linux-arm64" {
				machine = 183
			}
			binary.LittleEndian.PutUint16(data[18:20], machine)
			binary.LittleEndian.PutUint32(data[20:24], 1)
		}
		os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700)
		if e := os.WriteFile(filepath.Join(root, name), data, 0600); e != nil {
			t.Fatal(e)
		}
		m.Files[name] = digestBytes(data)
	}
	provenance := map[string]any{"status": "built-not-interop-tested", "target_platform": platform, "source": json.RawMessage(sourceLock), "runtime": map[string]string{"xpcshell": m.Files["runtime/xpcshell"], "libxul.so": m.Files["runtime/libxul.so"], "libnss3.so": m.Files["runtime/libnss3.so"], "platform.ini": m.Files["runtime/platform.ini"]}}
	record, err := json.Marshal(provenance)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "provenance.json"), record, 0600); err != nil {
		t.Fatal(err)
	}
	m.Files["provenance.json"] = digestBytes(record)
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
	if runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		return
	}
	if _, err := VerifyBundle(testBundle(t)); err == nil {
		t.Fatal("unsupported host accepted executable bundle")
	}
}

func TestBundleArchitectureCannotBeRelabeledOrMixed(t *testing.T) {
	for _, platform := range []string{"linux-amd64", "linux-arm64"} {
		t.Run(platform, func(t *testing.T) {
			root := testBundlePlatform(t, platform)
			if _, err := verifyBundlePlatform(root, platform); err != nil {
				t.Fatal(err)
			}
			other := "linux-amd64"
			if platform == other {
				other = "linux-arm64"
			}
			if _, err := verifyBundlePlatform(root, other); err == nil {
				t.Fatal("accepted other architecture")
			}
			for _, name := range []string{"runtime/xpcshell", "runtime/libxul.so", "runtime/libnss3.so", "foxtunnel-necko", "foxtunnel", "vetroffproxy", "lib/libnss3.so", "runtime/other-library.so"} {
				t.Run(name, func(t *testing.T) {
					mixed := testBundlePlatform(t, platform)
					donor := testBundlePlatform(t, other)
					donorName := name
					if name == "foxtunnel" || name == "vetroffproxy" || name == "lib/libnss3.so" || name == "runtime/other-library.so" {
						donorName = "foxtunnel-necko"
					}
					data, err := os.ReadFile(filepath.Join(donor, donorName))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.MkdirAll(filepath.Dir(filepath.Join(mixed, name)), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(mixed, name), data, 0600); err != nil {
						t.Fatal(err)
					}
					manifestPath := filepath.Join(mixed, "manifest.json")
					var m bundleManifest
					raw, _ := os.ReadFile(manifestPath)
					json.Unmarshal(raw, &m)
					m.Files[name] = digestBytes(data)
					raw, _ = json.Marshal(m)
					os.WriteFile(manifestPath, raw, 0600)
					if _, err := verifyBundlePlatform(mixed, platform); err == nil {
						t.Fatal("accepted rehashed mixed-architecture bundle")
					}
				})
			}
		})
	}
}

func TestBundleRejectsAmbiguousManifestAndRehashedSource(t *testing.T) {
	for _, kind := range []string{"duplicate-field", "case-alias", "duplicate-file", "rehashed-source"} {
		t.Run(kind, func(t *testing.T) {
			root := testBundle(t)
			manifest := filepath.Join(root, "manifest.json")
			data, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "duplicate-field":
				data = append([]byte(`{"schema":2,`), data[1:]...)
			case "case-alias":
				data = bytes.Replace(data, []byte(`"schema"`), []byte(`"Schema"`), 1)
			case "duplicate-file":
				data = bytes.Replace(data, []byte(`"files":{`), []byte(`"files":{"source-lock.json":"wrong",`), 1)
			case "rehashed-source":
				var m bundleManifest
				if err := json.Unmarshal(data, &m); err != nil {
					t.Fatal(err)
				}
				changed := []byte(`{"different":"source"}`)
				if err := os.WriteFile(filepath.Join(root, "source-lock.json"), changed, 0600); err != nil {
					t.Fatal(err)
				}
				m.Files["source-lock.json"] = digestBytes(changed)
				data, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(manifest, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyBundle(root); err == nil {
				t.Fatal("accepted ambiguous or source-mismatched bundle")
			}
		})
	}
}

func TestBundlePreservesCaseSensitiveFileNames(t *testing.T) {
	root := testBundle(t)
	manifest := filepath.Join(root, "manifest.json")
	raw, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var m bundleManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"LICENSE", "license"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		m.Files[name] = digestBytes([]byte(name))
	}
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBundle(root); err != nil {
		t.Fatal(err)
	}
}

func TestBundleRejectsRehashedProvenanceAndPrivilegedModes(t *testing.T) {
	for _, kind := range []string{"source", "runtime", "platform", "null-platform", "status", "duplicate", "file-mode", "directory-mode", "manifest-mode"} {
		t.Run(kind, func(t *testing.T) {
			root := testBundle(t)
			manifest := filepath.Join(root, "manifest.json")
			if kind == "file-mode" || kind == "directory-mode" || kind == "manifest-mode" {
				if runtime.GOOS == "windows" {
					t.Skip("POSIX modes")
				}
				name := "foxtunnel-necko"
				mode := os.FileMode(0700) | os.ModeSetuid
				if kind == "directory-mode" {
					name, mode = "runtime", 0700|os.ModeSetgid
				}
				if kind == "manifest-mode" {
					name = "manifest.json"
				}
				if err := os.Chmod(filepath.Join(root, name), mode); err != nil {
					t.Fatal(err)
				}
			} else {
				name := filepath.Join(root, "provenance.json")
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				var p map[string]any
				if err := json.Unmarshal(raw, &p); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "source":
					p["source"] = map[string]string{"wrong": "revision"}
				case "runtime":
					p["runtime"].(map[string]any)["libxul.so"] = "wrong"
				case "platform":
					p["target_platform"] = "linux-arm64"
				case "null-platform":
					p["target_platform"] = nil
				case "status":
					p["status"] = "unverified"
				}
				raw, err = json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "duplicate" {
					raw = append([]byte(`{"status":"wrong",`), raw[1:]...)
				}
				if err := os.WriteFile(name, raw, 0600); err != nil {
					t.Fatal(err)
				}
				var m bundleManifest
				data, err := os.ReadFile(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(data, &m); err != nil {
					t.Fatal(err)
				}
				m.Files["provenance.json"] = digestBytes(raw)
				data, err = json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifest, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := verifyBundle(root); err == nil {
				t.Fatal("accepted invalid provenance or privileged mode")
			}
		})
	}
}
