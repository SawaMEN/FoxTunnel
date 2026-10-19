# Native Linux TUN (experimental embedded Go TCP/IP)

**English** · [Русский](NATIVE-LINUX-TUN.md) · [Roadmap](../planning/ROADMAP.en.md)

`foxtunnel client --tun ftun0` starts a **native in-process Linux TUN**. An embedded gVisor Go TCP/IP stack (MIT-licensed tun2socks/v2 core library) handles IPv4/IPv6 TCP and UDP and forwards connections to the same FoxTunnel process's local SOCKS5 listener, then its authenticated TLS transport. **No sing-box process or executable is involved.**

Building from sources requires Go **1.26.3**; gVisor and tun2socks/v2 dependencies are pinned in `go.mod`/`go.sum`.

Run on an isolated Linux test workstation with `/dev/net/tun`, CAP_NET_ADMIN, numeric upstream server IP with verified TLS SNI/CA/pin, and UDP streaming enabled on both client and server:

~~~sh
foxtunnel client --link-file connection.txt --enable-udp --udp-stream --tun ftun0 --tun-mtu 1400
~~~

The program **never changes routes, DNS configuration, or firewall on its own**. Configure IPv4/IPv6 addresses and default routes toward TUN in an isolated network namespace, with an explicit exception for the upstream server IP on the physical interface. Install an external nftables fail-closed guard **before** changing routes, allowing only loopback, TUN, and the numeric server endpoint(s). The [Linux TUN companion](LINUX-TUN.en.md) can generate `killswitch.nft`; do **not** use its sing-box launcher for this mode. Avoid remote SSH setup because changing the firewall can sever access.

Current limitations: maximum **256 TCP flows**, **128 UDP sessions**, UDP **30-second idle timeout**, device MTU **1280–9000**. The downstream FoxTunnel UDP v2 wire format still limits a complete SOCKS UDP datagram to **1232 bytes**. There is **no automatic DNS hijack**: OS DNS must target a numeric remote resolver routed over TUN. Local DNS stubs and systemd-resolved may need separate configuration. The firewall is a host policy, not embedded; it is not reboot-persistent by itself. No guarantee is made about production leak resistance, traffic under fragmented UDP, ICMP or TSPU censorship.

Native in-process means gVisor Go code is linked directly into FoxTunnel; it is an external **library**, not a separately launched proxy, and not a brand-new from-scratch TCP/IP stack.

The [native Linux end-to-end CI](https://github.com/SawaMEN/FoxTunnel/actions/workflows/native-tun-e2e.yml) covers TCP IPv4/IPv6, UDP, numeric DNS, client failure, TUN shutdown, guard persistence and link down/up inside isolated network namespaces. **Native Linux end-to-end CI passed: 7 of 7 stage tasks implemented and verified within an isolated Linux lab.** This is not a production leak-resistance audit.

~~~sh
go test ./internal/nativetun
~~~
