package firefox

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"github.com/SawaMEN/VetroffProxy/internal/safejson"
)

//go:embed gecko.lock.json
var sourceLock []byte

const BundleProtocol = 1

type bundleManifest struct {
	Schema           int               `json:"schema"`
	HelperProtocol   int               `json:"helper_protocol"`
	Platform         string            `json:"platform"`
	SourceLockSHA256 string            `json:"source_lock_sha256"`
	ClientJSSHA256   string            `json:"client_js_sha256"`
	Files            map[string]string `json:"files"`
}

func digestBytes(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }

// VerifyBundle checks every packaged file, rejects extra files and links, and
// binds the runtime to this helper's source lock and embedded JS. Archive hashes
// must still be obtained from a trusted publisher: a manifest is not a signature.
func VerifyBundle(directory string) (string, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return "", errors.New("Firefox bundle requires Linux amd64 or ARM64")
	}
	return verifyBundlePlatform(directory, runtime.GOOS+"-"+runtime.GOARCH)
}

// Integrity validation is independent of the host's ability to execute Gecko.
func verifyBundle(directory string) (string, error) {
	return verifyBundlePlatform(directory, "linux-amd64")
}

func verifyBundlePlatform(directory, platform string) (string, error) {
	invalid := errors.New("incompatible or damaged Firefox bundle")
	absolute, e := filepath.Abs(directory)
	if e != nil {
		return "", invalid
	}
	// Freeze a version-directory symlink before verification and execution.
	// Switching a "current" pointer must not change the path we verified.
	absolute, e = filepath.EvalSymlinks(absolute)
	if e != nil {
		return "", invalid
	}
	root, e := os.OpenRoot(absolute)
	if e != nil {
		return "", invalid
	}
	defer root.Close()
	f, e := root.Open("manifest.json")
	if e != nil {
		return "", invalid
	}
	data, e := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	f.Close()
	if e != nil || len(data) > 4<<20 {
		return "", invalid
	}
	var m bundleManifest
	fields, e := safejson.DecodeObject(bytes.NewReader(data), 4<<20)
	if e != nil || len(fields) != 6 {
		return "", invalid
	}
	for _, name := range []string{"schema", "helper_protocol", "platform", "source_lock_sha256", "client_js_sha256", "files"} {
		if _, ok := fields[name]; !ok {
			return "", invalid
		}
	}
	if json.Unmarshal(data, &m) != nil {
		return "", invalid
	}
	if m.Schema != 1 || m.HelperProtocol != BundleProtocol || m.Platform != platform || (platform != "linux-amd64" && platform != "linux-arm64") || m.SourceLockSHA256 != digestBytes(sourceLock) || m.ClientJSSHA256 != digestBytes(clientScript) || len(m.Files) == 0 || len(m.Files) > 20000 {
		return "", invalid
	}
	for _, required := range []string{"runtime/xpcshell", "runtime/libxul.so", "runtime/libnss3.so", "runtime/platform.ini", "provenance.json", "source-lock.json", "vetroff-necko"} {
		if len(m.Files[required]) != 64 {
			return "", invalid
		}
	}
	if m.Files["source-lock.json"] != m.SourceLockSHA256 {
		return "", invalid
	}
	for name := range m.Files {
		if !fs.ValidPath(name) || path.Clean(name) != name || strings.Contains(name, `\`) {
			return "", invalid
		}
	}
	// Every ELF must match the native architecture, including secondary libraries.
	requiredELF := map[string]bool{"runtime/xpcshell": true, "runtime/libxul.so": true, "runtime/libnss3.so": true, "vetroff-necko": true, "vetroff": true, "lib/libnss3.so": true}
	machine := uint16(62)
	if platform == "linux-arm64" {
		machine = 183
	}
	seen := 0
	e = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return invalid
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return invalid
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return invalid
		}
		if entry.IsDir() {
			return nil
		}
		if name == "manifest.json" {
			return nil
		}
		if !entry.Type().IsRegular() || !fs.ValidPath(name) || path.Clean(name) != name {
			return invalid
		}
		want, ok := m.Files[name]
		if !ok || len(want) != 64 {
			return invalid
		}
		file, e := root.Open(name)
		if e != nil {
			return invalid
		}
		h := sha256.New()
		var header [64]byte
		n, readErr := io.ReadFull(file, header[:])
		if requiredELF[name] || (n >= 4 && bytes.Equal(header[:4], []byte{127, 'E', 'L', 'F'})) {
			kind := binary.LittleEndian.Uint16(header[16:18])
			if readErr != nil || !bytes.Equal(header[:7], []byte{127, 'E', 'L', 'F', 2, 1, 1}) || (kind != 2 && kind != 3) || binary.LittleEndian.Uint16(header[18:20]) != machine || binary.LittleEndian.Uint32(header[20:24]) != 1 {
				file.Close()
				return invalid
			}
		}
		h.Write(header[:n])
		_, e = io.Copy(h, file)
		file.Close()
		if e != nil || hex.EncodeToString(h.Sum(nil)) != want {
			return invalid
		}
		seen++
		return nil
	})
	if e != nil || seen != len(m.Files) {
		return "", invalid
	}
	if e := verifyBundleProvenance(root, m); e != nil {
		return "", invalid
	}
	return filepath.Join(absolute, "runtime", "xpcshell"), nil
}

func verifyBundleProvenance(root *os.Root, manifest bundleManifest) error {
	f, err := root.Open("provenance.json")
	if err != nil {
		return err
	}
	defer f.Close()
	object, err := safejson.DecodeObject(f, 4<<20)
	if err != nil {
		return err
	}
	var status string
	platform := "linux-amd64"
	var runtimeHashes map[string]string
	if raw, ok := object["target_platform"]; ok {
		platform = ""
		if json.Unmarshal(raw, &platform) != nil {
			return errors.New("invalid bundle provenance platform")
		}
	}
	if json.Unmarshal(object["status"], &status) != nil || status != "built-not-interop-tested" || platform != manifest.Platform || json.Unmarshal(object["runtime"], &runtimeHashes) != nil {
		return errors.New("invalid bundle provenance")
	}
	var expected, actual any
	if json.Unmarshal(sourceLock, &expected) != nil || json.Unmarshal(object["source"], &actual) != nil || !reflect.DeepEqual(expected, actual) {
		return errors.New("bundle provenance source mismatch")
	}
	for _, name := range []string{"xpcshell", "libxul.so", "libnss3.so", "platform.ini"} {
		if runtimeHashes[name] != manifest.Files["runtime/"+name] {
			return errors.New("bundle provenance runtime mismatch")
		}
	}
	return nil
}

// RunBundle validates before launching; callers can switch whole bundle
// directories atomically and roll back by selecting the previous directory.
func RunBundle(ctx context.Context, directory string, config Config, stdout, stderr io.Writer) error {
	runtimePath, e := VerifyBundle(directory)
	if e != nil {
		return e
	}
	return Run(ctx, runtimePath, config, stdout, stderr)
}
