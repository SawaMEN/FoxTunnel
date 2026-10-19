package webprofile

import "reflect"

// Comparison contains only initial handshake/framing metadata already retained
// by Profile. It excludes payload, HPACK values and timing/workload judgments.
type Comparison struct {
	Schema               int     `json:"schema"`
	Scope                string  `json:"scope"`
	ReferenceSource      string  `json:"reference_source"`
	CandidateSource      string  `json:"candidate_source"`
	InitialMetadataEqual bool    `json:"initial_metadata_equal"`
	Checks               []Check `json:"checks"`
	Limitations          string  `json:"limitations"`
}
type Check struct {
	Field     string `json:"field"`
	Equal     bool   `json:"equal"`
	Reference any    `json:"reference"`
	Candidate any    `json:"candidate"`
}

func Compare(reference, candidate Profile) Comparison {
	r := Comparison{Schema: 1, Scope: "initial-tls-h2-metadata", ReferenceSource: reference.Source,
		CandidateSource: candidate.Source, InitialMetadataEqual: true,
		Limitations: "Metadata agreement is not Firefox/Necko equivalence or censorship resistance. TLS 1.3-only and single-ALPN policies differ from the browser. Record sizes/timing require matched workloads and external packet captures."}
	add := func(name string, a, b any) {
		equal := reflect.DeepEqual(a, b)
		r.Checks = append(r.Checks, Check{name, equal, a, b})
		r.InitialMetadataEqual = r.InitialMetadataEqual && equal
	}
	a, b := reference.Hello, candidate.Hello
	add("tls.record_version", a.RecordVersion, b.RecordVersion)
	add("tls.legacy_version", a.LegacyVersion, b.LegacyVersion)
	add("tls.cipher_suites", a.CipherSuites, b.CipherSuites)
	add("tls.extensions", a.Extensions, b.Extensions)
	add("tls.supported_groups", a.SupportedGroups, b.SupportedGroups)
	add("tls.ec_point_formats", a.ECPointFormats, b.ECPointFormats)
	add("tls.supported_versions", a.SupportedVersions, b.SupportedVersions)
	add("tls.signature_algorithms", a.SignatureAlgorithms, b.SignatureAlgorithms)
	add("tls.key_share_groups", a.KeyShareGroups, b.KeyShareGroups)
	add("tls.alpn", a.ALPN, b.ALPN)
	add("tls.sni_present", a.SNI, b.SNI)
	add("tls.negotiated_alpn", reference.ALPN, candidate.ALPN)
	add("h2.initial_settings", reference.Settings, candidate.Settings)
	// Per-setting checks make partial receive-profile agreement visible even
	// when ordering or an additional setting still differs.
	settings := func(p Profile) map[uint16]uint32 {
		m := make(map[uint16]uint32)
		for _, s := range p.Settings {
			m[s.ID] = s.Value
		}
		return m
	}
	ra, rb := settings(reference), settings(candidate)
	value := func(m map[uint16]uint32, id uint16) any {
		v, ok := m[id]
		if !ok {
			return nil
		}
		return v
	}
	for _, s := range []struct {
		id   uint16
		name string
	}{{1, "header_table_size"}, {2, "enable_push"}, {4, "initial_window_size"}, {5, "max_frame_size"}, {6, "max_header_list_size"}} {
		add("h2."+s.name, value(ra, s.id), value(rb, s.id))
	}
	add("h2.connection_window_updates", reference.ConnectionWindow, candidate.ConnectionWindow)
	return r
}
