package profile

import "testing"

func TestAutoTLSInConnectionLinks(t *testing.T) {
	for _, mode := range []string{"h2-connect", "wss", "xhttp-stream-up", "h3-post"} {
		t.Run(mode, func(t *testing.T) {
			config := Config{Version: 1, Servers: []string{"https://example.org"}, Username: "alice", Password: "secret", Transport: mode}
			link, err := Encode(config)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Decode(link)
			if err != nil || parsed.TLSBackend != "auto" {
				t.Fatalf("automatic backend lost in link: %+v %v", parsed, err)
			}
		})
	}
	nssOnH3 := Config{Version: 1, Servers: []string{"https://example.org"}, Username: "alice", Password: "secret", Transport: "h3-post", TLSBackend: "nss"}
	if _, err := Encode(nssOnH3); err == nil {
		t.Fatal("explicit NSS over unsupported Go QUIC accepted")
	}
}
