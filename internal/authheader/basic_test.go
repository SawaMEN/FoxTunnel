package authheader

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func basic(name, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+secret))
}

func TestParseBoundsCanonicalAndDuplicates(t *testing.T) {
	const secret = "strong-unpredictable-credential-0123456789"
	for _, tc := range []struct {
		name string
		head http.Header
		want bool
	}{
		{"normal", http.Header{"Proxy-Authorization": {basic("alice", secret)}}, true},
		{"scheme-case", http.Header{"proxy-authorization": {"bAsIc " + strings.TrimPrefix(basic("alice", secret), "Basic ")}}, true},
		{"secret-colon", http.Header{"Proxy-Authorization": {basic("alice", "secret:with:colons")}}, true},
		{"missing", http.Header{}, false},
		{"duplicate-same-key", http.Header{"Proxy-Authorization": {basic("alice", secret), basic("alice", secret)}}, false},
		{"duplicate-mixed-case", http.Header{"Proxy-Authorization": {basic("alice", secret)}, "proxy-authorization": {basic("alice", secret)}}, false},
		{"too-large", http.Header{"Proxy-Authorization": {strings.Repeat("x", MaxHeaderBytes+1)}}, false},
		{"wrong-scheme", http.Header{"Proxy-Authorization": {"Bearer something"}}, false},
		{"empty-secret", http.Header{"Proxy-Authorization": {basic("alice", "")}}, false},
		{"empty-user", http.Header{"Proxy-Authorization": {basic("", secret)}}, false},
		{"control-in-name", http.Header{"Proxy-Authorization": {basic("a\nlice", secret)}}, false},
		{"whitespace", http.Header{"Proxy-Authorization": {basic("alice", secret) + " "}}, false},
		{"newline", http.Header{"Proxy-Authorization": {basic("alice", secret) + "\r\n"}}, false},
		{"invalid-base64", http.Header{"Proxy-Authorization": {"Basic %%%%"}}, false},
		{"too-long-user", http.Header{"Proxy-Authorization": {basic(strings.Repeat("a", 257), secret)}}, false},
		{"too-long-password", http.Header{"Proxy-Authorization": {basic("alice", strings.Repeat("p", 1025))}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name, pass, ok := Parse(tc.head)
			if ok != tc.want {
				t.Fatalf("accept=%v want %v", ok, tc.want)
			}
			if !ok && (name != "" || pass != "") {
				t.Fatal("rejected auth returned credentials")
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"", "Basic ", basic("alice", "strong-credential-0123456789"),
		"Basic %%%%", strings.Repeat("x", MaxHeaderBytes+1),
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		value := string(input)
		name, secret, ok := Parse(http.Header{"Proxy-Authorization": {value}})
		if ok {
			if len(name) == 0 || len(name) > 256 || len(secret) == 0 || len(secret) > 1024 {
				t.Fatal("accepted credential violates invariants")
			}
		} else if name != "" || secret != "" {
			t.Fatal("failed parser returned credentials")
		}
	})
}
