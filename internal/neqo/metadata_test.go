package neqo

import (
	"net/http"
	"testing"
)

func TestClassicCONNECTMetadata(t *testing.T) {
	for _, authority := range []string{"example.org:443", "192.0.2.1:80", "[2001:db8::1]:8443"} {
		r, _ := http.NewRequest(http.MethodConnect, "https://proxy.example/", nil)
		r.Host = authority
		r.Header.Set("Proxy-Authorization", "Basic test-only")
		metadata, err := requestMetadata(r)
		if err != nil {
			t.Fatal(err)
		}
		fields, err := takeFields(metadata)
		if err != nil || len(fields) != 6 || string(fields[0]) != "CONNECT" || len(fields[1]) != 0 || string(fields[2]) != authority || len(fields[3]) != 0 || string(fields[4]) != "proxy-authorization" {
			t.Fatalf("invalid classic CONNECT metadata: %v", err)
		}
	}
}

func TestCONNECTRejectsInvalidAuthority(t *testing.T) {
	for _, authority := range []string{"", "example.org", "example.org:0", "example.org:65536", ":443", "user@example.org:443", "example.org/path:443", "a b:443", "[::1]:-1"} {
		r, _ := http.NewRequest(http.MethodConnect, "https://proxy.example/", nil)
		r.Host = authority
		// An empty Host defaults to the origin for normal HTTP requests, but
		// CONNECT must carry an explicit destination authority.
		if _, err := requestMetadata(r); err == nil {
			t.Fatalf("accepted authority %q", authority)
		}
	}
}
