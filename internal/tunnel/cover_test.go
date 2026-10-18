package tunnel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoverSiteAndProbeResponses(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<h1>Public site</h1>"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".secret"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	cover, err := NewCover(root)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Username: "alice", Password: "secret", Cover: cover}
	for _, tc := range []struct {
		method, path string
		code         int
		body         string
	}{
		{"GET", "/", 200, "Public site"}, {"HEAD", "/", 200, ""},
		{"GET", "/.secret", 404, ""}, {"GET", "/empty/", 404, ""},
		{"CONNECT", "https://127.0.0.1:9", 404, ""},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.ProtoMajor = 2
			req.Header.Set("Proxy-Authorization", "Basic invalid")
			got := httptest.NewRecorder()
			server.ServeHTTP(got, req)
			if got.Code != tc.code || !strings.Contains(got.Body.String(), tc.body) {
				t.Fatalf("got %d %q", got.Code, got.Body.String())
			}
			if strings.Contains(got.Body.String(), "FoxTunnel") || strings.Contains(got.Body.String(), "secret") {
				t.Fatal("exposed identifying/private content")
			}
			expected := httptest.NewRecorder()
			cover.ServeHTTP(expected, req)
			if got.Code != expected.Code || got.Body.String() != expected.Body.String() {
				t.Fatal("probe differs from website handler")
			}
		})
	}
}
func TestCoverStripsProxyCredentials(t *testing.T) {
	called := false
	s := &Server{Cover: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get(paddingHeader) != "" {
			t.Error("leaked proxy credentials")
		}
	})}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Proxy-Authorization", "private")
	req.Header.Set(paddingHeader, paddingVersion)
	s.ServeHTTP(httptest.NewRecorder(), req)
	if !called || req.Header.Get("Proxy-Authorization") != "private" {
		t.Fatal("cover not called or request mutated")
	}
}

func TestCoverConfinesSymlinksAndHidesConfiguration(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("private-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "asset.txt")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server.json", "connection.txt", "cluster.json", "server.key"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("private-marker"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cover, err := NewCover(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"asset.txt", "server.json", "connection.txt", "cluster.json", "server.key"} {
		w := httptest.NewRecorder()
		cover.ServeHTTP(w, httptest.NewRequest("GET", "/"+name, nil))
		if w.Code != 404 || strings.Contains(w.Body.String(), "private-marker") {
			t.Fatal("public file escape", name, w.Code)
		}
	}
	if CheckPublicRoot(root, filepath.Join(root, "server.key")) == nil {
		t.Fatal("private key inside site accepted")
	}
	if err := CheckPublicRoot(root, outside); err != nil {
		t.Fatal(err)
	}
}
