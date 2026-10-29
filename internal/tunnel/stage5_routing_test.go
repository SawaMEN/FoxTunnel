package tunnel

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SawaMEN/VetroffProxy/internal/bond"
	"github.com/SawaMEN/VetroffProxy/internal/cluster"
	"github.com/SawaMEN/VetroffProxy/internal/xhttp"
)

// Handler-level matrix: ProtoMajor=3 exercises routing decisions, not a
// real UDP/QUIC handshake. Actual H3/TLS integration lives in separate tests.
func TestStage5UnauthorizedRouteMatrix(t *testing.T) {
	paths := []struct {
		name, method, path string
	}{
		{"ordinary", http.MethodGet, "/"},
		{"wss", http.MethodGet, wsPath},
		{"connect", http.MethodConnect, "/"},
		{"post", http.MethodPost, postPath},
		{"xhttp", http.MethodPost, xhttp.Path + "packet"},
		{"cluster", http.MethodGet, cluster.Path},
		{"bond", http.MethodPost, bond.Path},
		{"udp", http.MethodPost, udpPath},
		{"udp-stream", http.MethodPost, udpStreamPath},
	}
	for _, managed := range []bool{false, true} {
		authMode := "builtin"
		if managed {
			authMode = "managed"
		}
		t.Run(authMode, func(t *testing.T) {
			s := &Server{Username: "alice", Password: "secret", EnableUDP: true}
			if managed {
				s.Access = accessController(t)
			}
			for _, proto := range []int{1, 2, 3} {
				for _, route := range paths {
					for _, credentials := range []string{"absent", "invalid", "duplicated"} {
						t.Run(route.name+"/"+credentials+"/"+string(rune('0'+proto)), func(t *testing.T) {
							called := 0
							s.Cover = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								called++
								for key := range r.Header {
									if strings.EqualFold(key, "Proxy-Authorization") ||
										strings.HasPrefix(strings.ToLower(key), "x-vetroff-") {
										t.Errorf("private field leaked into public cover: %q", key)
									}
								}
								w.Header().Set("Content-Type", "text/plain")
								w.WriteHeader(http.StatusOK)
								_, _ = w.Write([]byte("ordinary cover"))
							})
							r := httptest.NewRequest(route.method, "https://cover.example"+route.path, nil)
							r.ProtoMajor = proto
							r.ProtoMinor = 0
							if proto == 1 {
								r.ProtoMinor = 1
							}
							r.TLS = &tls.ConnectionState{}
							if route.method == http.MethodConnect {
								r.Host = "target.example:443"
							}
							original := ""
							switch credentials {
							case "invalid":
								original = stage2Basic("alice", "invalid-password")
								r.Header.Set("Proxy-Authorization", original)
							case "duplicated":
								original = stage2Basic("alice", "invalid-password")
								r.Header["Proxy-Authorization"] = []string{original, original}
							}
							r.Header.Set("X-Vetroff-Padding", "initial-v1")
							r.Header.Set(targetHeader, "target.example:443")
							result := httptest.NewRecorder()
							s.ServeHTTP(result, r)
							if result.Code != http.StatusOK || result.Body.String() != "ordinary cover" || called != 1 {
								t.Fatalf("probe distinguished from cover, proto=%d route=%s status=%d calls=%d body=%q", proto, route.name, result.Code, called, result.Body.String())
							}
							if credentials != "absent" && r.Header.Get("Proxy-Authorization") != original {
								t.Fatal("cover modified the caller's authentication headers")
							}
							if r.Header.Get(targetHeader) == "" {
								t.Fatal("cover modified original target metadata")
							}
						})
					}
				}
			}
		})
	}
}

func TestStage5AuthenticatedLimitsAndPaddingAreNotCover(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, proto := range []int{2, 3} {
			for _, transport := range []string{"connect", "post"} {
				t.Run(transport+"/"+string(rune('0'+proto))+"/"+map[bool]string{false: "builtin", true: "managed"}[managed], func(t *testing.T) {
					called := 0
					s := &Server{Username: "alice", Password: "secret", MaxTunnels: 1}
					if managed {
						s.Access = accessController(t)
					}
					s.Cover = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						called++
						w.WriteHeader(http.StatusOK)
					})
					credentials := stage2Basic("alice", "secret")
					if managed {
						credentials = stage2Basic("alice", accessAlice)
					}
					makeRequest := func() *http.Request {
						method, urlPath := http.MethodConnect, "/"
						if transport == "post" {
							method, urlPath = http.MethodPost, postPath
						}
						r := httptest.NewRequest(method, "https://cover.example"+urlPath, nil)
						r.ProtoMajor = proto
						r.ProtoMinor = 0
						r.Host = "target.example:443"
						r.Header.Set("Proxy-Authorization", credentials)
						r.Header.Set(targetHeader, "target.example:443")
						return r
					}
					{
						r := makeRequest()
						r.Header.Set(paddingHeader, "unknown-mode")
						w := httptest.NewRecorder()
						s.ServeHTTP(w, r)
						if w.Code != http.StatusBadRequest || called != 0 {
							t.Fatalf("authenticated unsupported padding: %d, cover=%d", w.Code, called)
						}
					}
					{
						s.activeTunnels.Store(1)
						r := makeRequest()
						w := httptest.NewRecorder()
						s.ServeHTTP(w, r)
						if w.Code != http.StatusServiceUnavailable || called != 0 {
							t.Fatalf("authenticated capacity limit: %d, cover=%d", w.Code, called)
						}
						if s.activeTunnels.Load() != 1 {
							t.Fatal("admission accounting changed for rejected capacity")
						}
					}
				})
			}
		}
	}
}
