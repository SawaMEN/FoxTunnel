# Linux TUN for FoxTunnel — experimental stage 3

**English** · [Русский](LINUX-TUN.md) · [Documentation](../README.en.md)

This is an integration with **external sing-box 1.14+**, forwarding through FoxTunnel's local SOCKS5. It is **not native FoxTunnel TUN**. Generating a configuration does not change the system network or require root.

## Implemented 5 of 7 tasks (source only, no field verification)

- [x] Linux sing-box TUN configuration generator
- [x] TCP/UDP via local FoxTunnel SOCKS5; UDP v2 remains experimental
- [x] IPv4/IPv6 routes and explicit FoxTunnel server IP exceptions
- [x] TUN DNS capture with upstream numeric DNS over SOCKS5
- [x] nftables output DROP guard persisting after process crash, plus offline tests
- [ ] Isolated network-namespace trials: TCP, UDP, DNS, IPv6, failures and leaks
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

**Warning:** run.sh installs the DROP guard **before** sing-box starts. It may cut off SSH, LAN, updates and Internet access. Only loopback, TUN, and allowlisted server IP/port on the uplink are accepted. Guard stays on after a crash but may disappear after a reboot. Not production ready.

Linux local DNS stub 127.0.0.53 may bypass TUN DNS hijacking; off-host resolver traffic should be blocked by the guard, but this must be verified. Network namespaces, privileged firewall changes, DoH and network migration are not covered.

~~~sh
python3 -m unittest discover -s scripts -p test_linux_tun_companion.py -v
~~~

These are **offline generator tests**, not an operational TUN trial. References: [sing-box TUN](https://sing-box.sagernet.org/configuration/inbound/tun/) and [SOCKS outbound](https://sing-box.sagernet.org/configuration/outbound/socks/).
