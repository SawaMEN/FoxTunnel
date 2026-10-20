package tunnel

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Uses real TLS sockets and negotiated H1/H2. This is not synthetic ProtoMajor
// rewriting, and it does not claim browser or QUIC fingerprint similarity.
func TestStage5CoverHTTPSConditionalAndCache(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "docs"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"index.html":      "<html>Public page</html>",
		"docs/index.html": "<html>Documentation</html>",
		"docs/site.css":   "body{color:black}",
	}
	modified := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	cover, err := NewCover(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, testcase := range []struct {
		name      string
		h2        bool
		wantMajor int
	}{
		{"tls-http11", false, 1},
		{"tls-h2", true, 2},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			handler := &Server{Username: "alice", Password: "secret", Cover: cover}
			server := httptest.NewUnstartedServer(handler)
			server.EnableHTTP2 = testcase.h2
			server.StartTLS()
			defer server.Close()

			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			}
			do := func(method, path string, configure func(*http.Request)) (*http.Response, []byte) {
				t.Helper()
				req, err := http.NewRequest(method, server.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Proxy-Authorization", "Basic invalid-private-header")
				req.Header.Set("X-FoxTunnel-Padding", "unsupported")
				if configure != nil {
					configure(req)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				if err != nil {
					t.Fatal(err)
				}
				if resp.ProtoMajor != testcase.wantMajor {
					t.Fatalf("expected negotiated HTTP/%d, got %s", testcase.wantMajor, resp.Proto)
				}
				return resp, body
			}
			get, body := do(http.MethodGet, "/docs/site.css", nil)
			if get.StatusCode != http.StatusOK ||
				!bytes.Equal(body, []byte(files["docs/site.css"])) ||
				get.Header.Get("Content-Type") != "text/css; charset=utf-8" {
				t.Fatalf("TLS public CSS GET failed: %d %q %q", get.StatusCode, body, get.Header.Get("Content-Type"))
			}
			lastModified := get.Header.Get("Last-Modified")
			if lastModified == "" {
				t.Fatal("public static response lacks modification timestamp")
			}
			head, body := do(http.MethodHead, "/docs/site.css", nil)
			if head.StatusCode != http.StatusOK || len(body) != 0 ||
				head.ContentLength != int64(len(files["docs/site.css"])) {
				t.Fatalf("TLS public HEAD failed: %d %d %q", head.StatusCode, head.ContentLength, body)
			}
			notModified, body := do(http.MethodGet, "/docs/site.css", func(req *http.Request) {
				req.Header.Set("If-Modified-Since", lastModified)
			})
			if notModified.StatusCode != http.StatusNotModified || len(body) != 0 {
				t.Fatalf("conditional TLS GET failed: %d %q", notModified.StatusCode, body)
			}
			partial, body := do(http.MethodGet, "/docs/site.css", func(req *http.Request) {
				req.Header.Set("Range", "bytes=0-3")
			})
			if partial.StatusCode != http.StatusPartialContent || string(body) != "body" ||
				partial.Header.Get("Content-Range") == "" {
				t.Fatalf("TLS Range failed: %d %q", partial.StatusCode, body)
			}
			redirect, body := do(http.MethodGet, "/docs", nil)
			if redirect.StatusCode != http.StatusMovedPermanently ||
				redirect.Header.Get("Location") != "/docs/" || len(body) == 0 {
				t.Fatalf("directory redirect mismatch: %d %q %q", redirect.StatusCode, redirect.Header.Get("Location"), body)
			}
			page, body := do(http.MethodGet, "/", nil)
			if page.StatusCode != http.StatusOK || string(body) != files["index.html"] {
				t.Fatalf("public TLS page failed: %d %q", page.StatusCode, body)
			}
		})
	}
}
