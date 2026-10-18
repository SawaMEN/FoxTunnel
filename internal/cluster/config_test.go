package cluster

import (
	"strings"
	"testing"
)

func TestRejectAmbiguousTopology(t *testing.T) {
	valid := `{"v":1,"nodes":[{"url":"https://a.example","weight":4},{"url":"https://b.example","weight":1}]}`
	if _, err := DecodeConfig(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, `"weight":4`, `"weight":4,"weight":2`, 1),
		strings.Replace(valid, `"weight":4`, `"Weight":4`, 1),
		strings.Replace(valid, `"weight":4`, `"weight":0`, 1),
		strings.Replace(valid, `"weight":4`, `"weight":101`, 1),
		strings.Replace(valid, `https://b.example`, `https://A.example:0443/`, 1),
		strings.Replace(valid, `https://a.example`, `http://a.example`, 1),
		strings.Replace(valid, `https://a.example`, `https://u:p@a.example`, 1),
		strings.Replace(valid, `https://a.example`, `https://a.example/path`, 1),
		strings.Replace(valid, `https://a.example`, `https://a.example?`, 1),
		strings.Replace(valid, `https://a.example`, `https://a.example:65536`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"command":"run"`, 1),
		`{"v":1,"nodes":[{"url":"https://a.example","weight":1,"disabled":true}]}`,
		valid + `{}`, `null`, strings.Repeat(" ", MaxBytes+1),
	} {
		if _, err := DecodeConfig(strings.NewReader(raw)); err == nil {
			t.Fatalf("accepted invalid topology: %.100s", raw)
		}
	}
}

func TestManifestIdentityAndExpiry(t *testing.T) {
	valid := `{"v":1,"hub_id":"` + strings.Repeat("ab", 32) + `","valid_for":120,"nodes":[{"url":"https://a.example","weight":1}]}`
	if _, err := DecodeManifest(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, strings.Repeat("ab", 32), "short", 1),
		strings.Replace(valid, `"valid_for":120`, `"valid_for":0`, 1),
		strings.Replace(valid, `"valid_for":120`, `"valid_for":301`, 1),
		strings.Replace(valid, `"weight":1`, `"weight":1,"disabled":true`, 1),
	} {
		if _, err := DecodeManifest(strings.NewReader(raw)); err == nil {
			t.Fatal("invalid manifest accepted")
		}
	}
}

func FuzzClusterDecoder(f *testing.F) {
	f.Add(`{"v":1,"nodes":[{"url":"https://a.example","weight":1}]}`)
	f.Add(`{"v":1,"hub_id":"` + strings.Repeat("ab", 32) + `","valid_for":120,"nodes":[{"url":"https://a.example","weight":1}]}`)
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = DecodeConfig(strings.NewReader(raw))
		_, _ = DecodeManifest(strings.NewReader(raw))
	})
}
