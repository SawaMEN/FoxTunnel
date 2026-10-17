package tunnel

import (
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

// NewCover serves an operator-owned public directory, without directory listings
// or dotfiles. Put only public website assets here (including symlink targets).
// Using a local site avoids forwarding rejected proxy credentials to a backend.
func NewCover(root string) (http.Handler, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "open", Path: root, Err: fs.ErrInvalid}
	}
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		name := path.Clean("/" + r.URL.Path)
		for _, segment := range strings.Split(name, "/") {
			if strings.HasPrefix(segment, ".") {
				http.NotFound(w, r)
				return
			}
		}
		f, err := http.Dir(root).Open(name)
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
			index, err := http.Dir(root).Open(path.Join(name, "index.html"))
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
