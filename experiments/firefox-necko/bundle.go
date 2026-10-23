package firefox

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
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
	invalid := errors.New("incompatible or damaged Firefox bundle")
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return "", errors.New("Firefox bundle currently requires Linux amd64")
	}
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
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&m) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", invalid
	}
	if m.Schema != 1 || m.HelperProtocol != BundleProtocol || m.Platform != "linux-amd64" || m.SourceLockSHA256 != digestBytes(sourceLock) || m.ClientJSSHA256 != digestBytes(clientScript) || len(m.Files) == 0 || len(m.Files) > 20000 {
		return "", invalid
	}
	for _, required := range []string{"runtime/xpcshell", "runtime/libxul.so", "runtime/libnss3.so", "runtime/platform.ini", "provenance.json", "source-lock.json", "foxtunnel-necko"} {
		if len(m.Files[required]) != 64 {
			return "", invalid
		}
	}
	seen := 0
	e = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return invalid
		}
		if entry.Type()&os.ModeSymlink != 0 {
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
	return filepath.Join(absolute, "runtime", "xpcshell"), nil
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
