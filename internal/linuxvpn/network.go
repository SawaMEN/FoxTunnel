package linuxvpn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/SawaMEN/FoxTunnel/internal/ippacket"
	"github.com/SawaMEN/FoxTunnel/internal/safejson"
)

const ClientTable = "foxtunnel_vpn_client"
const ServerTable = "foxtunnel_vpn_server"

type ClientConfig struct {
	Version   int    `json:"v"`
	Interface string `json:"interface"`
	Underlay  string `json:"underlay"`
	Gateway   string `json:"gateway"` // Same address family as the literal proxy endpoint.
	IPv4      string `json:"ipv4"`
	IPv6      string `json:"ipv6"`
	DNS4      string `json:"dns4"`
	DNS6      string `json:"dns6"`
}
type ServerConfig struct {
	Version  int    `json:"v"`
	Underlay string `json:"underlay"`
	Peers    []Peer `json:"peers"`
}

func InterfaceName(s string) bool {
	if len(s) < 1 || len(s) > 15 || s == "lo" || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func ReadConfig(path string, out any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return ErrConfig
	}
	f, err := os.Open(path)
	if err != nil {
		return ErrConfig
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) || safejson.Decode(f, 128<<10, out) != nil {
		return ErrConfig
	}
	return nil
}
func (c ClientConfig) Validate(endpoint netip.Addr) error {
	_, _, err := (Peer{IPv4: c.IPv4, IPv6: c.IPv6}).Addresses()
	gateway, e := netip.ParseAddr(c.Gateway)
	d4, f := netip.ParseAddr(c.DNS4)
	d6, g := netip.ParseAddr(c.DNS6)
	if c.Version != 1 || !InterfaceName(c.Interface) || !strings.HasPrefix(c.Interface, "ftvpn") || !InterfaceName(c.Underlay) || c.Interface == c.Underlay || err != nil || e != nil || gateway.Is4() != endpoint.Is4() || !gateway.IsValid() || gateway.IsUnspecified() || gateway.IsMulticast() || f != nil || !d4.Is4() || !ippacket.Public(d4) || g != nil || !d6.Is6() || !ippacket.Public(d6) || !endpoint.IsValid() || endpoint.Is4In6() || endpoint.IsLoopback() || endpoint.IsUnspecified() || endpoint.IsMulticast() {
		return ErrConfig
	}
	return nil
}
func (s ServerConfig) Validate() error {
	if s.Version != 1 || !InterfaceName(s.Underlay) || len(s.Peers) == 0 || len(s.Peers) > 128 {
		return ErrConfig
	}
	ids, ips := map[string]bool{}, map[string]bool{}
	for _, p := range s.Peers {
		a, b, err := p.Addresses()
		if err != nil || len(p.ID) < 1 || len(p.ID) > 64 || ids[p.ID] || ips[a.String()] || ips[b.String()] {
			return ErrConfig
		}
		for _, c := range p.ID {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return ErrConfig
			}
		}
		ids[p.ID] = true
		ips[a.String()] = true
		ips[b.String()] = true
	}
	return nil
}

// Run invokes fixed executables without a shell; subprocess diagnostics are
// suppressed so private endpoints/configuration cannot enter application logs.
func Run(ctx context.Context, name string, args []string, input string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return ErrNetwork
	}
	return nil
}
func ClientRules(c ClientConfig, endpoint netip.Addr, port int, uid int) (string, error) {
	if c.Validate(endpoint) != nil || port < 1 || port > 65535 || uid < 0 {
		return "", ErrConfig
	}
	family := "ip"
	if endpoint.Is6() {
		family = "ip6"
	}
	return fmt.Sprintf(`table inet %s {
 chain output { type filter hook output priority -50; policy drop;
  oifname "lo" accept
  oifname "%s" ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
  oifname "%s" accept
  oifname "%s" meta skuid %d %s daddr %s tcp dport %d accept
  oifname "%s" meta skuid %d %s daddr %s udp dport %d accept
 }
}
`, ClientTable, c.Underlay, c.Interface, c.Underlay, uid, family, endpoint, port, c.Underlay, uid, family, endpoint, port), nil
}
func ServerRules(c ServerConfig) (string, error) {
	if c.Validate() != nil {
		return "", ErrConfig
	}
	// INPUT and FORWARD restrictions apply even when another base chain accepts.
	// No peer-to-peer routing, local host access or non-underlay forwarding.
	return fmt.Sprintf(`table inet %s {
 chain input { type filter hook input priority -50; policy accept;
  iifname "ftvs*" drop
 }
 chain forward { type filter hook forward priority -50; policy accept;
  iifname "ftvs*" oifname "%s" accept
  iifname "ftvs*" drop
  oifname "ftvs*" ct state established,related accept
  oifname "ftvs*" drop
 }
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
  ip saddr 100.96.0.0/24 oifname "%s" masquerade
  ip6 saddr fd62:666f:78::/64 oifname "%s" masquerade
 }
}
`, ServerTable, c.Underlay, c.Underlay, c.Underlay), nil
}
func CheckServerNetwork(ctx context.Context) error {
	for _, p := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		b, e := os.ReadFile(p)
		if e != nil || strings.TrimSpace(string(b)) != "1" {
			return ErrNetwork
		}
	}
	return Run(ctx, "nft", []string{"list", "table", "inet", ServerTable}, "")
}
func InstallTable(ctx context.Context, table, rules string) error {
	if table != ClientTable && table != ServerTable {
		return ErrConfig
	}
	// Never merge into, replace or flush a pre-existing ruleset/table.
	if Run(ctx, "nft", []string{"list", "table", "inet", table}, "") == nil {
		return ErrNetwork
	}
	return Run(ctx, "nft", []string{"-f", "-"}, rules)
}
func RemoveTable(ctx context.Context, table string) error {
	if table != ClientTable && table != ServerTable {
		return ErrConfig
	}
	return Run(ctx, "nft", []string{"delete", "table", "inet", table}, "")
}
func ConfigureDevice(ctx context.Context, name string, peer Peer, client bool) error {
	a, b, err := peer.Addresses()
	if err != nil || !InterfaceName(name) {
		return ErrConfig
	}
	actions := [][]string{{"link", "set", "dev", name, "addrgenmode", "none"}, {"link", "set", "dev", name, "mtu", strconv.Itoa(ippacket.MTU), "up"}}
	if client {
		actions = append(actions, []string{"addr", "add", a.String() + "/32", "dev", name}, []string{"-6", "addr", "add", b.String() + "/128", "dev", name, "nodad"})
	} else {
		actions = append(actions, []string{"route", "add", a.String() + "/32", "dev", name}, []string{"-6", "route", "add", b.String() + "/128", "dev", name})
	}
	for _, args := range actions {
		if Run(ctx, "ip", args, "") != nil {
			return ErrNetwork
		}
	}
	return nil
}
func EndpointRoute(c ClientConfig, endpoint netip.Addr, operation string) []string {
	prefix := endpoint.String() + "/32"
	family := "-4"
	if endpoint.Is6() {
		prefix = endpoint.String() + "/128"
		family = "-6"
	}
	return []string{family, "route", operation, prefix, "via", c.Gateway, "dev", c.Underlay}
}
func ConfigureClientRoutes(ctx context.Context, c ClientConfig, endpoint netip.Addr) error {
	// The endpoint escape route must exist before either default split route.
	if Run(ctx, "ip", EndpointRoute(c, endpoint, "add"), "") != nil {
		return ErrNetwork
	}
	for _, args := range [][]string{{"dns", c.Interface, c.DNS4, c.DNS6}, {"domain", c.Interface, "~."}, {"default-route", c.Interface, "yes"}} {
		if Run(ctx, "resolvectl", args, "") != nil {
			return ErrNetwork
		}
	}
	for _, family := range []string{"-4", "-6"} {
		prefixes := []string{"0.0.0.0/1", "128.0.0.0/1"}
		if family == "-6" {
			prefixes = []string{"::/1", "8000::/1"}
		}
		for _, prefix := range prefixes {
			if Run(ctx, "ip", []string{family, "route", "add", prefix, "dev", c.Interface}, "") != nil {
				return ErrNetwork
			}
		}
	}
	return nil
}

// EndpointRouteFree refuses overwriting an existing host route before enabling
// the persistent kill switch. Connected subnet/default routes remain untouched.
func EndpointRouteFree(ctx context.Context, endpoint netip.Addr) bool {
	family, prefix := "-4", endpoint.String()+"/32"
	if endpoint.Is6() {
		family, prefix = "-6", endpoint.String()+"/128"
	}
	cmd := exec.CommandContext(ctx, "ip", family, "-j", "route", "show", "exact", prefix)
	data, err := cmd.Output()
	if err != nil {
		return false
	}
	var routes []json.RawMessage
	return json.Unmarshal(data, &routes) == nil && len(routes) == 0
}
