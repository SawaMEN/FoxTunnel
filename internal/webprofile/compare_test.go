package webprofile

import (
	"encoding/json"
	"os"
	"testing"
)

func TestComparisonSeparatesMozillaGaps(t *testing.T) {
	load := func(name string) Profile {
		t.Helper()
		data, e := os.ReadFile("../../docs/measurements/2026-10-18/" + name)
		if e != nil {
			t.Fatal(e)
		}
		var p Profile
		if e = json.Unmarshal(data, &p); e != nil {
			t.Fatal(e)
		}
		return p
	}
	ref := load("firefox-158-linux.json")
	candidate := load("vetroff-nss-firefox158-receive.json")
	result := Compare(ref, candidate)
	if result.InitialMetadataEqual {
		t.Fatal("known TLS/H2 gaps hidden")
	}
	checks := map[string]Check{}
	for _, c := range result.Checks {
		checks[c.Field] = c
	}
	for _, name := range []string{"h2.header_table_size", "h2.initial_window_size", "h2.max_frame_size", "h2.connection_window_updates"} {
		if !checks[name].Equal {
			t.Fatal("expected receive agreement", name)
		}
	}
	for _, name := range []string{"tls.supported_versions", "tls.alpn", "h2.initial_settings", "h2.max_header_list_size"} {
		if checks[name].Equal {
			t.Fatal("known difference hidden", name)
		}
	}
	if !Compare(ref, ref).InitialMetadataEqual {
		t.Fatal("same profile differs")
	}
}
func TestComparisonIgnoresDerivedJA3AndWorkloadTiming(t *testing.T) {
	p := Profile{Schema: 1, Source: "reference"}
	q := p
	q.Source = "candidate"
	q.Hello.JA3 = "derived"
	q.Hello.JA3MD5 = "derived"
	q.Records = []Record{{Length: 100}}
	if !Compare(p, q).InitialMetadataEqual {
		t.Fatal("derived hashes/workload affected initial field comparison")
	}
	q.Hello.ALPN = []string{"h2"}
	if Compare(p, q).InitialMetadataEqual {
		t.Fatal("ALPN difference missed")
	}
}
