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
		name := path.Clean("/" + r.URL.Path)
		for _, segment := range strings.Split(name, "/") {
			lower := strings.ToLower(segment)
			ext := path.Ext(lower)
			if strings.HasPrefix(segment, ".") || lower == "server.json" || lower == "connection.txt" || lower == "cluster.json" || ext == ".key" || ext == ".pem" || ext == ".p12" || ext == ".pfx" {
				http.NotFound(w, r)
				return
			}
		}
		confined, err := os.OpenRoot(root)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer confined.Close()
		files := http.FileServer(http.FS(confined.FS()))
		relative := strings.TrimPrefix(name, "/")
		if relative == "" {
			relative = "."
		}
		f, err := confined.Open(relative)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		info, err := f.Stat()
		_ = f.Close()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if info.IsDir() {
			index, err := confined.Open(strings.TrimPrefix(path.Join(name, "index.html"), "/"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			stat, err := index.Stat()
			_ = index.Close()
			if err != nil || !stat.Mode().IsRegular() {
				http.NotFound(w, r)
				return
			}
		} else if !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	}), nil
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
