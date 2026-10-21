package tunnel

import (
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// NewCover serves an operator-owned public directory, without directory listings
// or dotfiles. Access is confined to root, including relative symlink targets.
// Using a local site avoids forwarding rejected proxy credentials to a backend.
func NewCover(root string) (http.Handler, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "open", Path: root, Err: fs.ErrInvalid}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		// Check the original path segments before cleaning. A dotfile must
		// not become a public path by hiding it behind ../ components.
		for _, part := range strings.Split(r.URL.Path, "/") {
			if forbiddenCoverSegment(part) {
				http.NotFound(w, r)
				return
			}
		}
		name := path.Clean("/" + r.URL.Path)
		confined, err := os.OpenRoot(root)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer confined.Close()
		relative := strings.TrimPrefix(name, "/")
		if relative == "" {
			relative = "."
		}
		file, info, err := openPublicFile(confined, relative)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if info.IsDir() {
			if !strings.HasSuffix(r.URL.Path, "/") {
				_ = file.Close()
				http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
				return
			}
			_ = file.Close()
			file, info, err = openPublicFile(confined, path.Join(relative, "index.html"))
			if err != nil || !info.Mode().IsRegular() {
				if file != nil {
					_ = file.Close()
				}
				http.NotFound(w, r)
				return
			}
		} else if !info.Mode().IsRegular() {
			_ = file.Close()
			http.NotFound(w, r)
			return
		}
		defer file.Close()
		if strings.HasSuffix(r.URL.Path, "/index.html") {
			http.Redirect(w, r, "./", http.StatusMovedPermanently)
			return
		}
		// Serve the same already-verified file descriptor. Do not let a
		// second FileServer.Open re-resolve a symlink after validation.
		http.ServeContent(w, r, info.Name(), info.ModTime(), file)
	}), nil
}

func forbiddenCoverSegment(segment string) bool {
	lower := strings.ToLower(segment)
	ext := path.Ext(lower)
	return strings.HasPrefix(segment, ".") ||
		lower == "server.json" || lower == "connection.txt" ||
		lower == "cluster.json" ||
		ext == ".key" || ext == ".pem" || ext == ".p12" || ext == ".pfx"
}

// openPublicFile checks every component for symlinks and forbidden names
// before opening a file from the confined root. Only already-opened regular
// files are served. Public directories must be controlled by the operator:
// untrusted writers must not be allowed to mutate the tree concurrently.
func openPublicFile(root *os.Root, relative string) (*os.File, os.FileInfo, error) {
	var componentInfo os.FileInfo
	var current string
	for _, segment := range strings.Split(relative, "/") {
		if segment == "" || segment == "." {
			continue
		}
		if forbiddenCoverSegment(segment) {
			return nil, nil, fs.ErrPermission
		}
		current = path.Join(current, segment)
		info, err := root.Lstat(current)
		if err != nil {
			return nil, nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, fs.ErrPermission
		}
		componentInfo = info
	}
	if current == "" {
		current = "."
	}
	if componentInfo == nil {
		var err error
		componentInfo, err = root.Lstat(current)
		if err != nil {
			return nil, nil, err
		}
	}
	// Reject FIFOs and devices before Open: opening them can block forever.
	if !componentInfo.IsDir() && !componentInfo.Mode().IsRegular() {
		return nil, nil, fs.ErrPermission
	}
	file, err := root.Open(current)
	if err != nil {
		return nil, nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(componentInfo, openedInfo) {
		_ = file.Close()
		return nil, nil, fs.ErrPermission
	}
	return file, openedInfo, nil
}

// CheckPublicRoot prevents accidentally publishing configured private files.
func CheckPublicRoot(root string, privateFiles ...string) error {
	public, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	public, err = filepath.Abs(public)
	if err != nil {
		return err
	}
	for _, name := range privateFiles {
		if name == "" {
			continue
		}
		absolute, err := filepath.Abs(name)
		if err != nil {
			return err
		}
		if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
			absolute = resolved
		}
		rel, err := filepath.Rel(public, absolute)
		if err != nil {
			return err
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fs.ErrPermission
		}
	}
	return nil
}
