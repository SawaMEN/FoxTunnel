#!/usr/bin/env python3
"""Generate an opt-in Linux TUN companion for FoxTunnel's local SOCKS5.

This tool does not modify routes, DNS, or firewall settings itself. The
generated root-only launcher checks configuration and installs a persistent,
fail-closed nftables output guard before sing-box starts.
Requires sing-box >= 1.14 for the generated DNS mode.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}$")
TABLE = "foxtunnel_tun_guard"


def interface(value: str) -> str:
    if not IDENT.fullmatch(value) or value == "lo":
        raise ValueError("interface must be a Linux name of at most 15 safe characters (not lo)")
    return value


def destination(value: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    """Accept numeric IPv4:port or [IPv6]:port only: DNS before VPN leaks."""
    if value.startswith("["):
        match = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:(\d+)", value)
        if not match:
            raise ValueError("endpoint must be IP:PORT or [IPv6]:PORT")
        ip_text, port_text = match.groups()
    else:
        match = re.fullmatch(r"([0-9.]+):(\d+)", value)
        if not match:
            raise ValueError("endpoint must use numeric IP, not a DNS name")
        ip_text, port_text = match.groups()
    try:
        ip = ipaddress.ip_address(ip_text)
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("invalid endpoint IP or port") from exc
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local:
        raise ValueError("endpoint cannot be loopback, unspecified, link-local or multicast")
    if not (1 <= port <= 65535):
        raise ValueError("endpoint port must be 1-65535")
    return ip, port


def dns_ip(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise ValueError("upstream DNS must be a remote numeric IP")
    return str(ip)


def make_config(
    endpoints: list[str],
    uplink: str,
    tun_name: str = "ftun0",
    socks_port: int = 1080,
    dns: str = "1.1.1.1",
    proto: str = "tcp",
) -> tuple[dict, str]:
    if not endpoints or len(endpoints) > 16:
        raise ValueError("provide 1-16 explicit tunnel server endpoints")
    wan = interface(uplink)
    tun = interface(tun_name)
    if wan == tun:
        raise ValueError("uplink and TUN device must be different")
    if not 1 <= socks_port <= 65535:
        raise ValueError("invalid SOCKS5 port")
    if proto not in ("tcp", "udp"):
        raise ValueError("carrier must be tcp or udp")
    server_ips = [destination(e) for e in endpoints]
    if len(set(server_ips)) != len(server_ips):
        raise ValueError("duplicate server endpoint")
    resolver = dns_ip(dns)

    # An explicit numeric endpoint remains routable outside the TUN. The guard
    # below allows only this endpoint on the actual uplink; not general bypass.
    excludes = sorted({
        f"{ip}/{32 if ip.version == 4 else 128}"
        for ip, _port in server_ips
    })
    sing_box = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [{
                "type": "udp",
                "tag": "remote-dns",
                "server": resolver,
                "detour": "foxtunnel-socks",
            }],
            "final": "remote-dns",
        },
        "inbounds": [{
            "type": "tun",
            "tag": "foxtunnel-tun",
            "interface_name": tun,
            "address": ["172.28.247.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 1400,
            "dns_mode": "hijack",
            "auto_route": True,
            "auto_redirect": True,
            "strict_route": True,
            "route_exclude_address": excludes,
        }],
        "outbounds": [{
            "type": "socks",
            "tag": "foxtunnel-socks",
            "server": "127.0.0.1",
            "server_port": socks_port,
            "version": "5",
        }],
        "route": {
            "rules": [{"port": 53, "action": "hijack-dns"}],
            "final": "foxtunnel-socks",
            "auto_detect_interface": True,
        },
    }

    # A separate base output chain with policy DROP prevents physical egress
    # when sing-box crashes or auto_route disappears. It remains until deleted.
    lines = [
        f"table inet {TABLE} {{",
        "  chain output {",
        "    type filter hook output priority -150; policy drop;",
        '    oifname "lo" accept',
        f'    oifname "{tun}" accept',
        # IPv6 neighbor discovery is necessary to reach an IPv6 server even
        # with a default-deny output chain. Restrict to NDP, hop limit 255,
        # and the explicit uplink; no unrestricted ICMPv6 or DNS bypass.
        f'    oifname "{wan}" ip6 hoplimit 255 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept',
    ]
    for ip, port in server_ips:
        family = "ip" if ip.version == 4 else "ip6"
        lines.append(
            f'    oifname "{wan}" {family} daddr {ip} '
            f'{proto} dport {port} accept'
        )
    lines.extend(["  }", "}", ""])
    return sing_box, "\n".join(lines)


def write_exclusive(path: Path, content: str, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
    path.chmod(mode)


LAUNCH = """#!/bin/sh
# Intentionally does NOT remove the firewall on program exit or failure.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "requires root" >&2; exit 1; }
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
command -v nft >/dev/null || { echo "install nftables first" >&2; exit 1; }
command -v sing-box >/dev/null || { echo "install sing-box 1.14+ first" >&2; exit 1; }
sing-box check -c "$base/sing-box.json"
nft -c -f "$base/killswitch.nft"
if nft list table inet foxtunnel_tun_guard >/dev/null 2>&1; then
  echo "guard already installed; inspect it, do not overwrite" >&2
  exit 1
fi
nft -f "$base/killswitch.nft"
echo "guard ACTIVE (persists if sing-box exits); to remove manually:" >&2
echo "  nft delete table inet foxtunnel_tun_guard" >&2
exec sing-box run -c "$base/sing-box.json"
"""

NOTES = """Linux TUN companion for FoxTunnel (experimental, NOT a native VPN).
Files: sing-box.json (TUN, routing, DNS via SOCKS), killswitch.nft, run.sh.

1. On a local Linux test machine, start FoxTunnel with its SOCKS listener
   on 127.0.0.1 and --enable-udp --udp-stream (or TCP only if not using UDP).
   Configure the FoxTunnel HTTPS URL with a NUMERIC IP and verified TLS SNI,
   so startup needs no direct DNS. Ensure ALL fallback entry IPs are listed
   during generation; unlisted IPs are blocked on the physical interface.
2. Run: sing-box check -c sing-box.json
3. Inspect the nft policy, confirm uplink/TUN interfaces and endpoints.
   WARNING: activating the output guard cuts off SSH, local LAN, updates and
   ordinary Internet traffic. Use a LOCAL console on a dedicated test host.
4. Start as root with ./run.sh; it enables the DROP guard before TUN routing.
5. Disconnect: stop sing-box (and FoxTunnel); the guard deliberately persists.
   To restore original network access at the LOCAL console:
       sudo nft delete table inet foxtunnel_tun_guard

Do NOT run remotely over SSH. Do NOT install this on a production router.
External sing-box 1.14+ is required. Valid JSON does not prove operational TUN,
DNS capture or leak prevention. Linux systemd-resolved local-stub DNS may not be
hijacked; the guard blocks its off-host DNS queries unless forwarded in-TUN.
This does not persist across reboots, and other network namespaces or privileged
firewall modifications are out of scope. Confirm IPv4/IPv6/DNS/leak behavior in
an isolated network namespace before production use.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", action="append", required=True,
                        help="FoxTunnel server numeric IP:port (repeat for fallbacks)")
    parser.add_argument("--uplink", required=True, help="physical network device (e.g., enp3s0)")
    parser.add_argument("--tun", default="ftun0")
    parser.add_argument("--socks-port", type=int, default=1080)
    parser.add_argument("--dns", default="1.1.1.1", help="remote DNS IP, accessed via SOCKS")
    parser.add_argument("--carrier", choices=("tcp", "udp"), default="tcp",
                        help="FoxTunnel outer carrier: TCP H2/WSS/XHTTP or UDP H3")
    parser.add_argument("--out", type=Path, required=True, help="new private output directory")
    args = parser.parse_args(argv)
    try:
        config, firewall = make_config(
            args.endpoint, args.uplink, args.tun, args.socks_port, args.dns, args.carrier
        )
        args.out.mkdir(mode=0o700)  # refuse existing directory
        write_exclusive(args.out / "sing-box.json", json.dumps(config, indent=2) + "\n", 0o600)
        write_exclusive(args.out / "killswitch.nft", firewall, 0o600)
        write_exclusive(args.out / "run.sh", LAUNCH, 0o700)
        write_exclusive(args.out / "README.txt", NOTES, 0o600)
    except (ValueError, OSError) as exc:
        parser.exit(2, f"generation failed: {exc}\n")
    print(f"Created {args.out}: configuration ONLY, no network changes applied.")
    print("Check sing-box.json and killswitch.nft before running as root.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
