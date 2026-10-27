// Package buildinfo describes the executable contract consumed by integrations.
package buildinfo

import (
	"github.com/SawaMEN/FoxTunnel/internal/contract"
	"github.com/SawaMEN/FoxTunnel/internal/neqo"
	"runtime"
)

const SDKSchema = contract.SDKSchema
const ProcessSchema = contract.ProcessSchema

const ProtocolDraft = contract.ProtocolDraft

var Version = "dev"
var Commit = "unknown"
var BuildDate = "unknown"
var Variant = ""
var Dirty = "true"

type Info struct {
	// FeatureStability is scoped to implemented wire modes; it does not version the Go API.
	FeatureStability  map[string]string `json:"feature_stability"`
	SDKSchema         int               `json:"sdk_schema"`
	ProcessSchema     int               `json:"process_schema"`
	Product           string            `json:"product"`
	IntegrationSchema int               `json:"integration_schema"`
	TransportEngines  []string          `json:"transport_engines"`
	QUICBackends      []string          `json:"quic_backends"`
	NeqoVersion       string            `json:"neqo_version,omitempty"`
	NeqoRevision      string            `json:"neqo_revision,omitempty"`
	NSSVersion        string            `json:"nss_version,omitempty"`
	Schema            int               `json:"schema"`
	Version           string            `json:"version"`
	Commit            string            `json:"commit"`
	BuildDate         string            `json:"build_date"`
	GOOS              string            `json:"goos"`
	GOARCH            string            `json:"goarch"`
	Variant           string            `json:"variant,omitempty"`
	GoVersion         string            `json:"go_version"`
	BuildFlavor       string            `json:"build_flavor"`
	TLSBackends       []string          `json:"tls_backends"`
	DefaultTLSBackend string            `json:"default_tls_backend"`
	ProtocolDraft     string            `json:"protocol_draft"`
	Experimental      bool              `json:"experimental"`
	Dirty             bool              `json:"dirty"`
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
	engines := []string{"legacy"}
	if runtime.GOOS == "linux" && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
		engines = append(engines, "necko")
	}
	if NSSAvailable {
		engines = append(engines, "mozilla")
	}
	quicBackends := []string{"quic-go"}
	var neqoVersion, neqoRevision string
	if neqo.Available {
		quicBackends = append(quicBackends, "neqo")
		neqoVersion, neqoRevision = neqo.Version, neqo.Revision
	}
	return Info{FeatureStability: map[string]string{"xhttp-stream-one": "stable", "xhttp-stream-up": "stable", "xhttp-packet-up": "stable", "bond": "stable", "bond-lanes": "stable", "bond-adaptive": "stable", "bond-autotune": "stable", "bond-traffic": "stable", "bond-route-smart": "stable"}, SDKSchema: SDKSchema, ProcessSchema: ProcessSchema, Product: "protocol-core", IntegrationSchema: 1, TransportEngines: engines, QUICBackends: quicBackends, NeqoVersion: neqoVersion, NeqoRevision: neqoRevision, NSSVersion: linkedNSSVersion(), Schema: 1, Version: Version, Commit: Commit, BuildDate: BuildDate, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Variant: Variant, GoVersion: runtime.Version(), BuildFlavor: Flavor, TLSBackends: backends, DefaultTLSBackend: defaultBackend, ProtocolDraft: ProtocolDraft, Experimental: true, Dirty: Dirty != "false"}
}
