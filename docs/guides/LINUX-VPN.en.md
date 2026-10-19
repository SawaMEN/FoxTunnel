# Stage six: experimental Linux TUN VPN

[Русский](LINUX-VPN.md)

`ip-v1` carries complete IP envelopes over the existing authenticated TLS/HTTP
stream. Linux kernels handle TCP, UDP, fragmentation and ICMP, without an
external tun2socks or userspace TCP implementation. IPv4/IPv6 use MTU 1280;
DNS uses the same tunnel. Ordinary SOCKS/TCP remains unchanged.

This is reliable-stream L3 encapsulation, including H3 streams, **not** QUIC
DATAGRAM, RFC 9484 CONNECT-IP or RFC 9298 CONNECT-UDP. TCP-over-TCP/head-of-line
blocking applies. No speed advantage, Firefox parity or field resistance is claimed.

Requirements: Linux root/CAP_NET_ADMIN, /dev/net/tun, iproute2 and nftables at both
ends; client also requires working systemd-resolved/resolvectl. Use managed users
from stage five, one IP session per account ID, and a direct common exit.
Legacy credentials, bond, discovery and padding are rejected for IP mode.
The private vetroff link must contain exactly one literal IP endpoint, explicit
verified SNI and normal CA/optional pin policy, avoiding bootstrap DNS.

All configuration/link files are regular mode 0600 files outside the public
root, without symlinks. Try dedicated Linux VMs first: the client blocks direct
egress for the whole network namespace, including existing SSH outside the VPN.

Server VPN file:

```json
{"v":1,"underlay":"eth0","peers":[{"id":"alice","ipv4":"100.96.0.2","ipv6":"fd62:666f:78::2"}]}
```

IDs match users.json. Addresses must be unique within 100.96.0.0/24 and
fd62:666f:78::/64 (up to 128 peers); do not overlap existing networks.
Enable IPv4/IPv6 forwarding explicitly, install the isolated firewall/NAT policy
once, then run the existing HTTPS server with --vpn-config:

```sh
sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
foxtunnel vpn-network --config /etc/foxtunnel/vpn-server.json
unset FOXTUNNEL_USER FOXTUNNEL_PASSWORD
foxtunnel server --listen :443 --cert /etc/foxtunnel/cert.pem \
  --key /etc/foxtunnel/key.pem --users-file /etc/foxtunnel/access/users.json \
  --users-state /etc/foxtunnel/access/usage.json \
  --vpn-config /etc/foxtunnel/vpn-server.json
```

`inet foxtunnel_vpn_server` supplies NAT44/NAT66, blocks TUN-to-host/peer access and
allows established/related return flows. Other firewall tables are untouched;
their DROP policies can still block VPN traffic. Forwarding persistence across
reboot is the operator's responsibility. Per-session nonpersistent ftvs<hash> TUN
devices and /32,/128 routes disappear when their FDs close. Managed revocation
and rotation cancel IP sessions too. A duplicate account session receives 409.

Client file:

```json
{"v":1,"interface":"ftvpn0","underlay":"eth0","gateway":"192.168.1.1","ipv4":"100.96.0.2","ipv6":"fd62:666f:78::2","dns4":"9.9.9.9","dns6":"2620:fe::fe"}
```

Use the real underlay/gateway (same family as proxy IP), the peer's assigned
addresses and explicit public DNS reachable from the exit. DNS values here are
configuration examples. Generate a normal private link with an IP URL and the
certificate name as SNI; never put its secret in command-line arguments.

```sh
foxtunnel vpn-client --config /etc/foxtunnel/vpn-client.json \
  --link-file /etc/foxtunnel/connection.txt
```

Optional --ca-cert supplies a private CA. Setup validates collisions, installs
the atomic blocking nft table, creates TUN, adds an exact endpoint escape route,
sets resolver link DNS/~./default-route and adds /1 IPv4/IPv6 defaults. TLS and IP
negotiation happen afterward. Partial installation failures remain blocked.
Existing defaults are preserved; existing interfaces/tables/exact endpoint routes
are refused. The output chain permits loopback, TUN and only the exact proxy IP/
TCP-UDP port for the process UID on the underlay. IPv6 neighbor discovery with
hoplimit 255 is allowed separately; underlay DNS/DHCP/other data is not allowed.

Disconnects close the failed stream without IP replay and retry session setup
with 1–10 second backoff. Freeze/resume and restoration of the same underlay can
recover; changing Wi-Fi/gateway requires explicit reconfiguration and remains
blocked meanwhile. Existing TCP sockets are not guaranteed across full restarts.

SIGTERM, SIGKILL, crashes, trust errors and unreachable servers **never remove**
the client nft policy. TUN/defaults disappear when its FD closes, but direct
IPv4/IPv6/DNS stays blocked. After a crash explicitly disconnect before starting
again; a restart without an explicit disconnect window is not implemented yet.

```sh
# Deliberately restores ordinary direct egress:
foxtunnel vpn-down --config /etc/foxtunnel/vpn-client.json \
  --link-file /etc/foxtunnel/connection.txt
```

This checks our table exists, removes link DNS/TUN/exact endpoint route, then
only foxtunnel_vpn_client. Other DNS/default configuration was preserved. Stop
the server before removing its policy with vpn-network --config FILE --remove.
The kill switch covers its current network namespace; it does not protect
administrator-created alternate namespaces or survive reboot unless policy is
loaded separately at boot. No systemd/boot configuration is installed.

Wire: explicit X-FoxTunnel-Network: ip-v1 and ip.foxtunnel.invalid:1 authority;
unsupported servers reject it. Each record is uint16 big-endian length plus a
20–1280-byte IP packet. Invalid lengths, IPv4 checksums/options, IPv6 routing/
option headers and unsupported protocols fail closed. TCP/UDP/ICMP and ordinary
fragments are supported. Fixed peer sources, public destinations and return
destinations are checked before kernel injection or delivery. --allow-private
explicitly relaxes address policy; host/peer isolation still applies in nftables.

Managed quota_bytes counts full IP envelopes, including IP/transport headers
and actual TCP retransmissions, in both directions; stream framing/TLS/HTTP is
excluded. This differs from ordinary TCP/bond payload accounting but uses the
same durable account ledger. Whole packets are charged before injection/delivery;
insufficient remaining quota closes the session without a partial packet.
max_tunnels counts one IP session, not every inner flow; kernel conntrack/NAT has
its own system limits. Two fixed-buffer pumps and stream/TUN backpressure avoid
unbounded Go queues. Roaming, DHCP renewal, boot firewall and sustained platform
validation remain future work.

SDK Client.DialIP returns IPConn.ReadPacket/WritePacket, IPMTU and Close; Client.Close
owns IP sessions too. ctx controls setup. ServerConfig.IPHandler is an opt-in
managed host handler; NewServer itself never changes host networking.

Checks include parser/framing fuzz, negotiation rejection, IPv4/IPv6 over seven
transports, NSS/opt-in Neqo, accounting and revocation. Separate privileged CI
uses three disposable namespaces and real TUN/NAT/nft for TCP/UDP/DNS/IPv6,
freeze/resume, carrier loss, crash blocking and explicit disconnect. Its DNS
fixture uses private netns resolv.conf; real systemd-resolved integration still
needs operational validation on the deployment machine.
