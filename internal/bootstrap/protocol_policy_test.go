package bootstrap

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/contract"
	"github.com/SawaMEN/FoxTunnel/internal/profile"
)

func TestProtocolPolicyStrictSetup(t *testing.T) {
	for _, transport := range []string{"h2-connect", "h3-post"} {
		t.Run(transport, func(t *testing.T) {
			o := fixture(t, "strict.example")
			o.ProtocolPolicy, o.Transport, o.EnableUDP = contract.ProtocolStrict, transport, true
			if err := Generate(o); err != nil {
				t.Fatal(err)
			}
			c, err := ReadServer(filepath.Join(o.Output, "server.json"))
			if err != nil || c.ProtocolPolicy != contract.ProtocolStrict || c.BondHub || c.ClusterFile != "" || c.BondUpstream != "" || !c.EnableUDP {
				t.Fatal("strict setup created an incompatible server", c, err)
			}
			p, err := profile.ReadSecretFile(filepath.Join(o.Output, "connection.txt"))
			if err != nil || p.ProtocolPolicy != contract.ProtocolStrict || p.Bond || p.Discover || p.Transport != transport {
				t.Fatal("strict setup lost policy or enabled bond", err)
			}
			if _, err := os.Stat(filepath.Join(o.Output, "cluster.json")); !os.IsNotExist(err) {
				t.Fatal("strict setup created discovery topology")
			}
		})
	}
}

func TestProtocolPolicySetupPreservesLegacyAndRejectsInvalid(t *testing.T) {
	o := fixture(t, "legacy.example")
	o.ProtocolPolicy = contract.ProtocolLegacy
	if err := Generate(o); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(o.Output, "server.json"))
	if bytes.Contains(data, []byte("protocol_policy")) {
		t.Fatal("legacy setup changed old server JSON format")
	}
	for _, mode := range []contract.ProtocolPolicy{"unknown", contract.ProtocolStrict} {
		bad := fixture(t, "bad.example")
		bad.ProtocolPolicy = mode
		if mode == contract.ProtocolStrict {
			bad.JoinLinkFile = filepath.Join(o.Output, "connection.txt")
		}
		if err := Generate(bad); err == nil {
			t.Fatal("invalid strict join or policy accepted")
		}
		if _, err := os.Stat(bad.Output); !os.IsNotExist(err) {
			t.Fatal("invalid setup wrote configuration")
		}
	}
}

func TestProtocolPolicyServerRejectsMalformedAndBond(t *testing.T) {
	o := fixture(t, "strict.example")
	o.ProtocolPolicy = contract.ProtocolStrict
	if err := Generate(o); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(o.Output, "server.json")
	base, _ := os.ReadFile(path)
	for _, value := range []string{`null`, `""`, `"auto"`, `true`, `1`, `[]`, `"STRICT"`, `"strict", "protocol_policy": "legacy"`} {
		data := bytes.Replace(base, []byte(`"protocol_policy": "strict"`), []byte(`"protocol_policy": `+value), 1)
		if bytes.Equal(base, data) {
			t.Fatal("fixture policy replacement failed")
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadServer(path); err == nil {
			t.Fatal("malformed server policy silently became legacy")
		}
	}
	var c ServerConfig
	if err := json.Unmarshal(base, &c); err != nil {
		t.Fatal(err)
	}
	for _, extension := range []string{"hub", "relay", "discovery"} {
		bad := c
		switch extension {
		case "hub":
			bad.BondHub = true
		case "relay":
			bad.BondUpstream = "https://relay.example"
		case "discovery":
			bad.BondHub, bad.ClusterFile = true, "cluster.json"
		}
		data, _ := json.Marshal(bad)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadServer(path); err == nil {
			t.Fatal("strict server accepted an unnegotiated extension")
		}
	}
}
