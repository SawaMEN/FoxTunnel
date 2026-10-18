package profile

import (
	"encoding/base64"
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
