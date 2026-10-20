package tunnel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// NewCover must never use a benign URL alias to follow an internal symlink
// to hidden operator credentials. os.OpenRoot guards escaping the root but
// intentionally allows internal symlinks; cover has a stricter policy.
func TestStage5CoverDeniesInternalSymlinkAliases(t *testing.T) {
	root := t.TempDir()
	const marker = "PRIVATE-COVER-ALIAS-NOT-PUBLIC"
	for filename, body := range map[string]string{
		".secret":     marker,
		"server.json": marker,
		"index.html":  "<html>Public page</html>",
	} {
		if err := os.WriteFile(filepath.Join(root, filename), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "hidden"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hidden", ".token"), []byte(marker), 0600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"alias.txt":         ".secret",
		"safe-looking.json": "server.json",
		"linked-index.html": "index.html",
		"directory-alias":   "hidden",
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
	}
	cover, err := NewCover(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, requestPath := range []string{
		"/alias.txt",
		"/safe-looking.json",
		"/linked-index.html",
		"/directory-alias/.token",
		"/.secret",
		"/server.json",
		"/hidden/.token",
		"/.secret/../index.html",
		"/hidden/../server.json",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+requestPath, func(t *testing.T) {
				got := httptest.NewRecorder()
				cover.ServeHTTP(got, httptest.NewRequest(method, requestPath, nil))
				if got.Code != http.StatusNotFound || strings.Contains(got.Body.String(), marker) {
					t.Fatalf("unsafe cover file served: %s %s: status=%d body=%q", method, requestPath, got.Code, got.Body.String())
				}
			})
		}
	}
}

func TestStage5CoverServesPinnedPublicFiles(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "docs")
	if err := os.Mkdir(docs, 0700); err != nil {
		t.Fatal(err)
	}
	for filename, data := range map[string]string{
		"index.html":      "<html>Public cover site</html>",
		"docs/index.html": "<html>Docs home</html>",
		"docs/style.css":  "body { color: black; }",
	} {
		if err := os.WriteFile(filepath.Join(root, filename), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cover, err := NewCover(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, expected string
	}{
		{"/", "Public cover site"},
		{"/docs/", "Docs home"},
		{"/docs/style.css", "body { color: black; }"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			cover.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), tc.expected) {
				t.Fatalf("public content not served status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
	for _, redirect := range []struct{ from, to string }{
		{"/docs", "/docs/"},
		{"/docs/index.html", "./"},
		{"/index.html", "./"},
	} {
		w := httptest.NewRecorder()
		cover.ServeHTTP(w, httptest.NewRequest(http.MethodGet, redirect.from, nil))
		if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != redirect.to {
			t.Fatalf("canonical cover redirect %s: %d %q", redirect.from, w.Code, w.Header().Get("Location"))
		}
	}
	w := httptest.NewRecorder()
	cover.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/docs/style.css", nil))
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("HEAD response incorrect: status=%d body=%q content-type=%q", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/docs/style.css", nil)
	r.Header.Set("Range", "bytes=0-3")
	cover.ServeHTTP(w, r)
	if w.Code != http.StatusPartialContent || w.Body.String() != "body" {
		t.Fatalf("Range response incorrect: %d %q", w.Code, w.Body.String())
	}
	for _, method := range []string{http.MethodPost, http.MethodConnect, http.MethodPut} {
		w = httptest.NewRecorder()
		cover.ServeHTTP(w, httptest.NewRequest(method, "/docs/style.css", nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("unexpected method response: %s => %d", method, w.Code)
		}
	}
}

func TestStage5CoverUnauthorizedTunnelMetadataIsolation(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("ordinary home"), 0600); err != nil {
		t.Fatal(err)
	}
	cover, err := NewCover(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, managed := range []bool{false, true} {
		for _, method := range []string{http.MethodGet, http.MethodConnect, http.MethodPost} {
			s := &Server{Username: "public-user", Password: "secret", Cover: cover}
			if managed {
				s.Access = accessController(t)
			}
			r := httptest.NewRequest(method, "https://cover.example/", nil)
			r.ProtoMajor = 2
			r.Header = http.Header{
				"Proxy-Authorization": {"Basic fake-secret-for-cover"},
				"X-FoxTunnel-Padding": {"secret-metadata"},
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			wantStatus := http.StatusOK
			if method != http.MethodGet {
				wantStatus = http.StatusNotFound
			}
			if w.Code != wantStatus {
				t.Fatalf("managed=%v method=%s status=%d want=%d", managed, method, w.Code, wantStatus)
			}
			if strings.Contains(w.Body.String(), "fake-secret") || strings.Contains(w.Body.String(), "secret-metadata") {
				t.Fatal("private metadata appeared in cover")
			}
		}
	}
}
