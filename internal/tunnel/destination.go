package tunnel

import "net/netip"

// Conservative egress policy, not a copy of IANA's Globally Reachable flag.
// Translation/transition space can route to embedded private IPv4 addresses;
// protocol-assignment and documentation space is deliberately excluded too.
// Sources: IANA IPv4/IPv6 Special-Purpose Address Registries (2026-10-20).
var prohibitedDestinations = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var publicIPv6 = netip.MustParsePrefix("2000::/3")

func safePublicIP(ip netip.Addr) bool {
	// Keep scope IDs out of default egress even when the address itself looks
	// public. Unmap before filtering so mapped private IPv4 cannot bypass it.
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	// Deny NAT64 (including unknown local translation formats), unallocated
	// IPv6 space and other special ranges outside global unicast allocation.
	if ip.Is6() && !publicIPv6.Contains(ip) {
		return false
	}
	for _, prefix := range prohibitedDestinations {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
