package profile

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/SawaMEN/FoxTunnel/internal/contract"
)

func TestProtocolPolicyLegacyExportsAndStrictRoundTrip(t *testing.T) {
	c := Config{Version: 1, Servers: []string{"https://node.example"}, Username: "alice", Password: "private-policy-secret"}
	oldLink, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	c.ProtocolPolicy = contract.ProtocolLegacy
	legacyLink, err := Encode(c)
	if err != nil || legacyLink != oldLink {
		t.Fatal("explicit legacy changed the old profile format")
	}
	data, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(legacyLink, Scheme+"://"))
	if strings.Contains(string(data), "protocol_policy") {
		t.Fatal("legacy link gained a field rejected by old clients")
	}
	c.ProtocolPolicy = contract.ProtocolStrict
	strictLink, err := Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(strictLink)
	if err != nil || got.ProtocolPolicy != contract.ProtocolStrict {
		t.Fatal("strict policy lost in round-trip", err)
	}
}

func TestProtocolPolicyRejectsMalformedAndAmbiguousProfiles(t *testing.T) {
	base := `"v":1,"servers":["https://node.example"],"username":"alice","password":"private-policy-secret"`
	for _, value := range []string{`null`, `""`, `"STRICT"`, `"auto"`, `"private-policy-secret"`, `true`, `1`, `{}`, `[]`} {
		link := Scheme + "://" + base64.RawURLEncoding.EncodeToString([]byte(`{`+base+`,"protocol_policy":`+value+`}`))
		if _, err := Decode(link); err == nil || strings.Contains(err.Error(), "private-policy-secret") {
			t.Fatal("invalid policy was accepted or echoed")
		}
	}
	for _, fields := range []string{`"protocol_policy":"strict","protocol_policy":"legacy"`, `"protocol_policy":"strict","Protocol_policy":"legacy"`} {
		link := Scheme + "://" + base64.RawURLEncoding.EncodeToString([]byte(`{`+base+`,`+fields+`}`))
		if _, err := Decode(link); err == nil {
			t.Fatal("ambiguous policy silently disabled strict")
		}
	}
	for _, discover := range []bool{false, true} {
		c := Config{Version: 1, ProtocolPolicy: contract.ProtocolStrict, Servers: []string{"https://node.example"}, Username: "alice", Password: "secret", Bond: true, Discover: discover}
		if !discover {
			c.Servers = append(c.Servers, "https://second.example")
		}
		if _, err := Encode(c); err == nil {
			t.Fatal("strict profile accepted unnegotiated bond/discovery")
		}
	}
}
