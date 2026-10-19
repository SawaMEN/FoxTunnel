# Linux TUN for FoxTunnel — experimental stage 3

**English** · [Русский](LINUX-TUN.md) · [Documentation](../README.en.md)

This is an integration with **external sing-box 1.14+**, forwarding through FoxTunnel's local SOCKS5. It is **not native FoxTunnel TUN**. Generating a configuration does not change the system network or require root.

## Implemented 5 of 7 tasks (source only, no field verification)

- [x] Linux sing-box TUN configuration generator
- [x] TCP/UDP via local FoxTunnel SOCKS5; UDP v2 remains experimental
- [x] IPv4/IPv6 routes and explicit FoxTunnel server IP exceptions
- [x] TUN DNS capture with upstream numeric DNS over SOCKS5
- [x] nftables output DROP guard persisting after process crash, plus offline tests
- [ ] Isolated network-namespace trials: **partial** — CI now tests real IPv4/IPv6 TCP, UDP, direct DNS blocking and nft guard retention after the test server exits; **sing-box TUN, end-to-end FoxTunnel, interface changes and comprehensive leak checks remain unverified**.
- [ ] Native TUN without an external sing-box dependency

**5/7 counts implemented code components, not verified network security.**

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

**This is a real-kernel firewall test, NOT a sing-box TUN, encrypted FoxTunnel or comprehensive leak test.** Without explicit opt-in it is skipped. See [CI workflow](https://github.com/SawaMEN/FoxTunnel/actions/workflows/tun-netns.yml).
