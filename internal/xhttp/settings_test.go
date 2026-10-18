package xhttp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSettingsValidation(t *testing.T) {
	for _, c := range []struct{ path, host string }{{"/api/upload", "Route.Example:8443"}, {"/api/v1/", "[2001:db8::1]:443"}, {"", "127.0.0.1"}} {
		s, err := Normalize(c.path, c.host)
		if err != nil || !strings.HasSuffix(s.Path, "/") || s.Host != strings.ToLower(c.host) {
			t.Fatal(s, err)
		}
		again, err := Normalize(s.Path, s.Host)
		if err != nil || again != s {
			t.Fatal("unstable settings")
		}
	}
	for _, path := range []string{"/", "relative", "//api/", "/api//a", "/a/../b", "/a/./b", "/api?q=1", "/api#f", "/api%2f", "/api\\x", "/api x", strings.Repeat("/x", 129)} {
		if _, err := Normalize(path, ""); err == nil {
			t.Fatal("unsafe path accepted", path)
		}
	}
	for _, host := range []string{"https://example.com", "user@example.com", "example.com/path", "example.com?x", "example.com#x", "example.com:", "example.com:0", "example.com:65536", "example.com:0443", "example.com\r\nX-Test: yes", "example.com ", "[example.com]", "2001:db8::1", "[fe80::1%eth0]", "other..example", ".example", "example."} {
		if _, err := Normalize("", host); err == nil {
			t.Fatal("unsafe Host accepted", host)
		}
	}
}
func TestSettingsRouteIsolation(t *testing.T) {
	s, _ := Normalize("/private/api", "Route.Example")
	for _, c := range []struct {
		target, host string
		want         bool
	}{{"/private/api/", "route.example", true}, {"/private/api/" + testID + "/0", "route.example", true}, {"/private/api/", "other.example", false}, {Path, "route.example", false}, {"/private/api", "route.example", false}, {"/private/api/" + testID + "/00", "route.example", false}, {"/private/api/../", "route.example", false}} {
		r := httptest.NewRequest("POST", "https://node"+c.target, nil)
		r.Host = c.host
		if got := MatchesAt(r, s); got != c.want {
			t.Fatal(c.target, c.host, got)
		}
	}
}
func FuzzSettings(f *testing.F) {
	f.Add("/api/v1/", "example.com")
	f.Add("/a/../b", "bad:host")
	f.Add("", "[::1]:443")
	f.Fuzz(func(t *testing.T, path, host string) {
		s, err := Normalize(path, host)
		if err != nil {
			return
		}
		again, err := Normalize(s.Path, s.Host)
		if err != nil || s != again || !strings.HasPrefix(s.Path, "/") || !strings.HasSuffix(s.Path, "/") {
			t.Fatal("unstable or ambiguous settings")
		}
	})
}
