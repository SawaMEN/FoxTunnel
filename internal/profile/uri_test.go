package profile

import (
	"crypto/x509"
	"encoding/base64"
	"github.com/SawaMEN/FoxTunnel/internal/tlsidentity"
	"reflect"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	input := Config{Version: 1, Servers: []string{"https://a.example", "https://[2001:db8::1]:8443"}, Username: "пользователь", Password: "p:@/?#%🔑", TLSBackend: "nss", Bond: true, Pipeline: "8", ConnectTimeout: "12s", AttemptTimeout: "2s"}
	link, err := Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "vetroff://") {
		t.Fatal("wrong scheme")
	}
	got, err := Read(strings.NewReader(link + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	normalized := input
	if err := normalized.normalize(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, normalized) {
		t.Fatal("connection profile changed")
	}
}

func TestCoordinatorOnlyLink(t *testing.T) {
	c := Config{Version: 1, Servers: []string{"https://main.example"}, Username: "alice", Password: "secret", Bond: true, Discover: true, SNI: "main.example", PinSHA256: tlsidentity.Pin(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("key")}), Encryption: "tls13"}
	link, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(link)
	if err != nil || !got.Discover || !got.Bond || len(got.Servers) != 1 {
		t.Fatal("single coordinator did not roundtrip", err)
	}
	if got.SNI != c.SNI || got.PinSHA256 != c.PinSHA256 || got.Encryption != "tls13" {
		t.Fatal("TLS settings lost in link")
	}
	c.Bond = false
	if _, err := Encode(c); err == nil {
		t.Fatal("discovery without bonding accepted")
	}
	c.Bond = true
	c.Servers = append(c.Servers, "https://other.example")
	if _, err := Encode(c); err == nil {
		t.Fatal("ambiguous coordinator and explicit paths accepted")
	}
}
func TestRejectUnsafeOrAmbiguousLinks(t *testing.T) {
	valid := `{"v":1,"servers":["https://a.example"],"username":"alice","password":"secret-marker"}`
	wrap := func(data string) string { return "vetroff://" + base64.RawURLEncoding.EncodeToString([]byte(data)) }
	badJSON := []string{
		strings.Replace(valid, `"v":1`, `"v":2`, 1),
		strings.Replace(valid, `"password":"secret-marker"`, `"password":"secret-marker","password":"other"`, 1),
		strings.Replace(valid, `"password":"secret-marker"`, `"password":"secret-marker","Password":"other"`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"ca_cert":"/private/file"`, 1),
		strings.Replace(valid, `https://a.example`, `http://a.example`, 1),
		strings.Replace(valid, `https://a.example`, `https://user:secret-marker@a.example`, 1),
		strings.Replace(valid, `https://a.example`, `https://a.example/path`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"bond":true`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"tls":"insecure"`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"encryption":"none"`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"encryption":"tls12"`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"sni":"other.example:443"`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"pin_sha256":"invalid"`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"pipeline":"256"`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"connect_timeout":"24h"`, 1),
		strings.Replace(valid, `["https://a.example"]`, `["https://a.example","https://A.example:443"]`, 1),
		valid + `{}`, `null`,
	}
	links := []string{"https://anything", "vetroff://bad!", "vetroff://", strings.Repeat("x", MaxLinkBytes+1), wrap(valid) + "#label", wrap(valid) + "?x=y", wrap(valid) + "/path"}
	for _, data := range badJSON {
		links = append(links, wrap(data))
	}
	for _, link := range links {
		_, err := Decode(link)
		if err == nil {
			t.Error("invalid link accepted")
		}
		if err != nil && (strings.Contains(err.Error(), "secret-marker") || strings.Contains(err.Error(), link) && len(link) > 32) {
			t.Fatal("link leaked in error")
		}
	}
}
func FuzzLinkDecoder(f *testing.F) {
	link, _ := Encode(Config{Version: 1, Servers: []string{"https://a.example"}, Username: "alice", Password: "sample"})
	f.Add(link)
	identityLink, _ := Encode(Config{Version: 1, Servers: []string{"https://a.example"}, Username: "alice", Password: "sample", SNI: "vpn.example", PinSHA256: tlsidentity.Pin(&x509.Certificate{RawSubjectPublicKeyInfo: []byte("key")})})
	f.Add(identityLink)
	f.Add("vetroff://bad!")
	f.Fuzz(func(t *testing.T, raw string) {
		config, err := Decode(raw)
		if err != nil {
			return
		}
		encoded, err := Encode(config)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(encoded)
		if err != nil || !reflect.DeepEqual(config, again) {
			t.Fatal("successful profile does not roundtrip")
		}
	})
}

func TestNativeTransportProfiles(t *testing.T) {
	for _, mode := range []string{"h2-connect", "h2-post", "wss", "h3-post", "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"} {
		c := Config{Version: 1, Servers: []string{"https://main.example"}, Username: "alice", Password: "secret", Transport: mode}
		link, err := Encode(c)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Decode(link)
		if err != nil || parsed.Transport != mode {
			t.Fatal("lost native transport", err)
		}
		c.TLSBackend = "nss"
		_, err = Encode(c)
		if (err != nil) != (mode == "h3-post") {
			t.Fatal("unsafe TLS backend combination", mode, err)
		}
	}
	c := Config{Version: 1, Servers: []string{"https://main.example"}, Username: "alice", Password: "secret", Transport: "xhttp"}
	if _, err := Encode(c); err == nil {
		t.Fatal("unimplemented XHTTP accepted")
	}
	legacy := "vetroff://" + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1,"servers":["https://main.example"],"username":"alice","password":"secret"}`))
	parsed, err := Decode(legacy)
	if err != nil || parsed.Transport != "h2-connect" {
		t.Fatal("legacy default changed", err)
	}
}
