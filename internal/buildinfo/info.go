// Package buildinfo describes the executable contract consumed by integrations.
package buildinfo

import "runtime"

const ProtocolDraft = "foxtunnel-draft-0"

var Version = "dev"
var Commit = "unknown"
var BuildDate = "unknown"
var Variant = ""
var Dirty = "true"

type Info struct {
	NSSVersion        string   `json:"nss_version,omitempty"`
	Schema            int      `json:"schema"`
	Version           string   `json:"version"`
	Commit            string   `json:"commit"`
	BuildDate         string   `json:"build_date"`
	GOOS              string   `json:"goos"`
	GOARCH            string   `json:"goarch"`
	Variant           string   `json:"variant,omitempty"`
	GoVersion         string   `json:"go_version"`
	BuildFlavor       string   `json:"build_flavor"`
	TLSBackends       []string `json:"tls_backends"`
	DefaultTLSBackend string   `json:"default_tls_backend"`
	ProtocolDraft     string   `json:"protocol_draft"`
	Experimental      bool     `json:"experimental"`
	Dirty             bool     `json:"dirty"`
}

func Current() Info {
	backends := []string{"go"}
	if NSSAvailable {
		backends = append(backends, "nss")
	}
	defaultBackend := "go"
	if NSSAvailable {
		defaultBackend = "nss"
	}
	return Info{NSSVersion: linkedNSSVersion(), Schema: 1, Version: Version, Commit: Commit, BuildDate: BuildDate, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Variant: Variant, GoVersion: runtime.Version(), BuildFlavor: Flavor, TLSBackends: backends, DefaultTLSBackend: defaultBackend, ProtocolDraft: ProtocolDraft, Experimental: true, Dirty: Dirty != "false"}
}
