package tunnel

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/access"
)

func stage2Basic(name, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+password))
}

func TestStage2LegacyAuthorizationRejectsDuplicateAndOversized(t *testing.T) {
	s := &Server{Username: "alice", Password: "secret"}
	for _, tc := range []struct {
		name string
		head http.Header
		ok   bool
	}{
		{"valid", http.Header{"Proxy-Authorization": {stage2Basic("alice", "secret")}}, true},
		{"incorrect-password", http.Header{"Proxy-Authorization": {stage2Basic("alice", "wrong")}}, false},
		{"duplicate", http.Header{"Proxy-Authorization": {stage2Basic("alice", "secret"), stage2Basic("alice", "secret")}}, false},
		{"mixed-key-casing", http.Header{"Proxy-Authorization": {stage2Basic("alice", "secret")}, "proxy-authorization": {stage2Basic("alice", "secret")}}, false},
		{"large", http.Header{"Proxy-Authorization": {strings.Repeat("A", 2049)}}, false},
		{"newline", http.Header{"Proxy-Authorization": {stage2Basic("alice", "secret") + "\n"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)
			r.ProtoMajor = 2
			r.Header = tc.head
			if got := s.authorized(r); got != tc.ok {
				t.Fatalf("auth=%v want %v", got, tc.ok)
			}
		})
	}
}

func TestStage2ManagedAccessMatchesLegacyHeaderPolicy(t *testing.T) {
	const strong = "strong-credential-for-access-123456789"
	c, err := access.New(access.Document{
		Version: 1, Users: []access.User{{ID: "alice", Username: "alice", Password: strong}},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, tc := range []struct {
		name string
		head http.Header
		ok   bool
	}{
		{"valid", http.Header{"Proxy-Authorization": {stage2Basic("alice", strong)}}, true},
		{"duplicate", http.Header{"Proxy-Authorization": {stage2Basic("alice", strong), stage2Basic("alice", strong)}}, false},
		{"mixed-key-casing", http.Header{"Proxy-Authorization": {stage2Basic("alice", strong)}, "proxy-authorization": {stage2Basic("alice", strong)}}, false},
		{"oversized", http.Header{"Proxy-Authorization": {strings.Repeat("A", 2049)}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodConnect, "https://proxy.example", nil)
			req.Header = tc.head
			ctx, done, err := c.Begin(req)
			if tc.ok {
				if err != nil || ctx == nil || done == nil {
					t.Fatalf("valid credentials refused: %v", err)
				}
				done()
			} else if err == nil {
				if done != nil {
					done()
				}
				t.Fatal("invalid request admitted")
			}
		})
	}
}

func TestStage2CoverStripsAllProxyMetadataForBothModes(t *testing.T) {
	legacy := &Server{Username: "alice", Password: "secret"}
	managed := &Server{Access: accessController(t)}
	for _, s := range []*Server{legacy, managed} {
		s.Cover = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for key := range r.Header {
				if strings.EqualFold(key, "Proxy-Authorization") ||
					strings.HasPrefix(strings.ToLower(key), "x-foxtunnel-") {
					t.Errorf("private header leaked to public cover: %q", key)
				}
			}
			w.WriteHeader(http.StatusNotFound)
		})
		for _, method := range []string{http.MethodGet, http.MethodConnect} {
			r := httptest.NewRequest(method, "https://proxy.example/", nil)
			r.ProtoMajor = 2
			r.Header = http.Header{
				"Proxy-Authorization":      {"Basic private"},
				"X-FoxTunnel-Padding":      {"initial-v1"},
				"X-FoxTunnel-Target":       {"sensitive.example:443"},
				"X-Foxtunnel-New-Metadata": {"hidden"},
				"x-foxtunnel-lower":        {"hidden"},
			}
			result := httptest.NewRecorder()
			s.ServeHTTP(result, r)
			if result.Code != http.StatusNotFound {
				t.Errorf("cover returned unexpected %d", result.Code)
			}
			if r.Header.Get("Proxy-Authorization") == "" {
				t.Fatal("caller header map was modified")
			}
		}
	}
}
