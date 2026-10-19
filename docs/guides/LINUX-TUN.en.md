# Linux TUN for FoxTunnel — experimental stage 3

**English** · [Русский](LINUX-TUN.md) · [Documentation](../README.en.md)

This guide covers the **external sing-box 1.14+** option, forwarding through FoxTunnel's local SOCKS5. A separate **[native Linux TUN](NATIVE-LINUX-TUN.en.md)** implementation now embeds gVisor TCP/IP inside FoxTunnel without sing-box. Generating the companion configuration does not change the system network or require root.

## Implemented 7 of 7 tasks (source and isolated Linux CI)

- [x] Linux sing-box TUN configuration generator
- [x] TCP/UDP via local FoxTunnel SOCKS5; UDP v2 remains experimental
- [x] IPv4/IPv6 routes and explicit FoxTunnel server IP exceptions
- [x] TUN DNS capture with upstream numeric DNS over SOCKS5
- [x] nftables output DROP guard persisting after process crash, plus offline tests
- [x] Isolated Linux network namespaces: **full app → sing-box TUN → SOCKS5 FoxTunnel → TLS 1.3 → exit** for TCP IPv4/IPv6, UDP v2, tunneled DNS; blocked direct traffic after stopping FoxTunnel and sing-box; link-down/link-up simulation. **Not a comprehensive leak audit of real production hosts.**
- [x] Native TUN with embedded gVisor stack in FoxTunnel, without sing-box ([guide](NATIVE-LINUX-TUN.en.md)); isolated end-to-end CI passed

**7/7 tasks are implemented and have passed dedicated isolated Linux CI tests.** This does not prove leak resistance in all environments.

## Generate

Requirements: Linux, Python 3.11+, sing-box 1.14+ and nftables. Run this on a **local lab workstation**, never over SSH on a remote VPS.

Configure FoxTunnel SOCKS5 to listen only at 127.0.0.1:1080. Its upstream HTTPS URL must use a **numeric server IP**, with TLS certificate name validated separately via SNI to avoid pre-VPN DNS. Include all fallback server IPs.

~~~sh
python3 scripts/linux_tun_companion.py \
  --endpoint 198.51.100.42:443 \
  --uplink enp3s0 --tun ftun0 \
  --socks-port 1080 --dns 1.1.1.1 \
  --carrier tcp --out /tmp/foxtunnel-tun-lab
~~~

198.51.100.42 is a **documentation-only address**, not a real endpoint. Replace it with your actual server IP. Use --carrier udp for HTTP/3. Files in the new private directory: sing-box.json, killswitch.nft, run.sh and README.txt.

~~~sh
sing-box check -c /tmp/foxtunnel-tun-lab/sing-box.json
sudo nft -c -f /tmp/foxtunnel-tun-lab/killswitch.nft
sudo /tmp/foxtunnel-tun-lab/run.sh
# After stopping services, at the LOCAL console:
sudo nft delete table inet foxtunnel_tun_guard
~~~

**Warning:** run.sh installs the DROP guard **before** sing-box starts. The nftables chain uses `filter` priority, after sing-box `auto_redirect` hooks, so tunneled traffic is not accidentally rejected before interception. It may cut off SSH, LAN, updates and Internet access. Only loopback, TUN, and allowlisted server IP/port on the uplink are accepted. Guard stays on after a crash but may disappear after a reboot. Not production ready.

Linux local DNS stub 127.0.0.53 may bypass TUN DNS hijacking; off-host resolver traffic should be blocked by the guard, but this must be verified. Network namespaces, privileged firewall changes, DoH and network migration are not covered.

~~~sh
python3 -m unittest discover -s scripts -p test_linux_tun_companion.py -v
~~~

These are **offline generator tests**, not an operational TUN trial. References: [sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/) and [SOCKS outbound](https://sing-box.sagernet.org/configuration/outbound/socks/).

## Real-kernel nft guard laboratory (NOT live TUN)

`scripts/test_linux_tun_netns.py` creates two isolated Linux network namespaces connected by a veth pair, with no Internet access. It checks allowlisted IPv4/IPv6 TCP, blocked unlisted ports, denied direct UDP/DNS, a UDP-only transport variant and retention of the output DROP policy after the mock server exits. The firewall allows narrowly scoped IPv6 NDP Neighbor Solicitation/Advertisement (hop limit 255) on the selected uplink; without NDP, even allowlisted IPv6 connections could fail.

Opt in on a dedicated Linux machine with root, iproute2 and nftables:

~~~sh
sudo -E env FOXTUNNEL_TUN_NETNS=1 python3 -m unittest discover -s scripts -p test_linux_tun_netns.py -v
~~~

**The first netns workflow tests the firewall only. A second workflow exercises actual sing-box TUN and encrypted FoxTunnel end-to-end.** Without explicit opt-in it is skipped. See [CI workflow](https://github.com/SawaMEN/FoxTunnel/actions/workflows/tun-netns.yml).

## Full isolated sing-box + FoxTunnel end-to-end lab

The [Linux TUN end-to-end workflow](https://github.com/SawaMEN/FoxTunnel/actions/workflows/tun-e2e.yml) builds the current FoxTunnel source, verifies a pinned SHA-256 of sing-box **1.14.1**, creates two new Linux network namespaces and runs an actual TUN and authenticated FoxTunnel TLS 1.3 carrier. It checks TCP IPv4/IPv6, UDP stream v2, intercepted DNS over the remote test resolver, denied direct egress after the FoxTunnel and sing-box processes stop, and uplink down/up. Only reserved 198.18.0.0/15 test addresses and local test certificates are used; host routes/firewall and the Internet are untouched.

**Progress: 7/7.** Native TUN with embedded TCP/IP is implemented in FoxTunnel and passed a separate CI without sing-box. Production leak audits, multi-homed failover, native OS stub resolver behavior and field evidence are separate readiness work.
