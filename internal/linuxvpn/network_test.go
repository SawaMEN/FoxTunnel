package linuxvpn

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNetworkPolicyBounds(t *testing.T) {
	c := ClientConfig{Version: 1, Interface: "ftvpn0", Underlay: "eth0", Gateway: "192.0.2.1", IPv4: "100.96.0.2", IPv6: "fd62:666f:78::2", DNS4: "9.9.9.9", DNS6: "2620:fe::fe"}
	endpoint := netip.MustParseAddr("192.0.2.2")
	rules, err := ClientRules(c, endpoint, 443, 1001)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"policy drop", "meta skuid 1001 ip daddr 192.0.2.2 tcp dport 443", "oifname \"ftvpn0\" accept", "nd-neighbor-solicit"} {
		if !strings.Contains(rules, want) {
			t.Fatal("missing policy", want, rules)
		}
	}
	if strings.Contains(rules, "ct state established") || strings.Contains(rules, "%!") {
		t.Fatal("unrestricted egress or formatting failure", rules)
	}
	for _, name := range []string{"lo", "ftvpn0\" accept", "a/b", "--help", strings.Repeat("x", 16)} {
		bad := c
		bad.Interface = name
		if _, err := ClientRules(bad, endpoint, 443, 1001); err == nil {
			t.Fatal("unsafe interface accepted", name)
		}
	}
	c.Gateway = "fe80::1"
	if c.Validate(endpoint) == nil {
		t.Fatal("mismatched gateway family")
	}
	c.Gateway = "192.0.2.1"
	c.DNS4 = "127.0.0.1"
	if c.Validate(endpoint) == nil {
		t.Fatal("direct local DNS accepted")
	}
	server := ServerConfig{Version: 1, Underlay: "eth0", Peers: []Peer{{ID: "alice", IPv4: "100.96.0.2", IPv6: "fd62:666f:78::2"}}}
	rules, err = ServerRules(server)
	if err != nil || !strings.Contains(rules, "iifname \"ftvs*\" drop") || !strings.Contains(rules, "ct state established,related accept") {
		t.Fatal(rules, err)
	}
	server.Peers = append(server.Peers, server.Peers[0])
	if server.Validate() == nil {
		t.Fatal("duplicate peer accepted")
	}
}
