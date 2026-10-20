# Features and configuration

[Home](../README.en.md) · [Getting started](START.en.md) · [Русский](FEATURES.md)

FoxTunnel starts as a local SOCKS5 TCP proxy connected to an authenticated HTTPS server:

~~~text
Application → SOCKS5 (127.0.0.1:1080) → FoxTunnel client
            → encrypted HTTPS transport → FoxTunnel server → destination
~~~

The server sees connection destinations. FoxTunnel is **not** an anonymity network or a mature whole-device VPN.

## Transports

| Transport | Purpose |
|---|---|
| \`h2-connect\` | Default TCP forwarding over HTTP/2 |
| \`h2-post\` | Alternate HTTP/2 POST streaming |
| \`h3-post\` | HTTP/3 over QUIC; needs a working UDP path |
| \`wss\` | WebSocket over TLS |
| \`xhttp-stream-one\`, \`xhttp-stream-up\`, \`xhttp-packet-up\` | Experimental XHTTP variants |

The selected transport must be supported by both ends. A \`--link-file\` preserves its configured transport.

## Mozilla mode

Regular builds use Go TLS and quic-go. NSS is Mozilla's TLS library; Neqo is its experimental Rust QUIC/H3 implementation. Neither is the full Firefox network stack.

On a **compatible native Linux amd64 build**, opt in with:

~~~bash
./foxtunnel client --engine mozilla --link-file connection.txt
~~~

This does not force an H3 connection if the file specifies another carrier. Neqo can use a controlled NSS/H2 reachability fallback **before** a request is sent. TLS identity errors never allow an insecure downgrade.

Optional local diagnostics: \`--engine-status-interval 10s\`; the public Go SDK has \`Status()\` and \`NotifyNetworkChange()\`. Fingerprint equivalence with Firefox and censorship bypass remain **unproven**.

## Experimental UDP ASSOCIATE

UDP is disabled by default. Add \`--enable-udp\` when running \`setup\` or configuring the server, then start the client with:

~~~bash
./foxtunnel client --link-file connection.txt --enable-udp
~~~

For the separate persistent multiplexed UDP carrier:

~~~bash
./foxtunnel client --link-file connection.txt --enable-udp --udp-stream
~~~

Both sides must support the configured mode. The implementation has datagram/session limits and is **not** interchangeable with native UDP VPN routing.

## Experimental native Linux TUN

~~~bash
./foxtunnel client --link-file connection.txt \
  --enable-udp --udp-stream --tun ftun0 --tun-mtu 1400
~~~

Requires Linux \`/dev/net/tun\`, \`CAP_NET_ADMIN\` and UDP enabled at the server. FoxTunnel embeds a Go TCP/IP stack, without requiring an external sing-box process for this mode.

The binary only opens the TUN. Use the explicit source-tree launcher for IPv4/IPv6 routing, DNS and a persistent kill switch (root, Python 3, iproute2, nftables, systemd-resolved):

~~~bash
sudo --preserve-env=FOXTUNNEL_USER,FOXTUNNEL_PASSWORD python3 scripts/linux_native_vpn.py \
  --endpoint 203.0.113.10:443 --uplink enp3s0 --dns 1.1.1.1 -- \
  /absolute/path/foxtunnel client --server https://203.0.113.10 \
  --sni vpn.example.com \
  --enable-udp --udp-stream --tun ftun0 --tun-mtu 1400
~~~

Set credentials through `FOXTUNNEL_USER` and `FOXTUNNEL_PASSWORD` first. Replace the example IP, use a numeric client URL with verified TLS SNI, list every fallback endpoint, and use `--carrier udp` for outer H3. `/etc/resolv.conf` must use systemd-resolved; DNS goes through TUN. `--dns-mode none` requires separately managed DNS (e.g. a network namespace).

The launcher checks table 51821 and rule priorities 18000–18016, installs the guard before starting the client, and adds separate IPv4/IPv6 policy routes without replacing existing routes. On normal exit or client crash it removes only its own routing/DNS changes. The nft table persists and blocks physical egress except loopback, NDP and explicit carrier endpoints. **Use a local console: SSH and LAN are blocked too.** To restore access explicitly:

~~~bash
sudo nft delete table inet foxtunnel_tun_guard
~~~

Killing the launcher itself with SIGKILL may leave its policy rules; inspect them before restarting. The guard does not survive reboot or cover other namespaces. CI tests isolated netns forwarding and crash blocking; resolved configuration has unit coverage, while a production host leak audit remains necessary. UDP SOCKS packets are limited to 1232 bytes including headers; IP fragmentation and arbitrary IP protocols are unsupported. A separate optional sing-box companion remains available.

## Multi-node and access control

Optional cluster ingress, bond streams, fallback servers and managed user quotas are available. Start with a single server. Advanced modes need compatible identities and an operator-maintained cluster configuration. View supported options with \`foxtunnel --help\`, \`foxtunnel server --help\`, and \`foxtunnel access --help\`.

## Security essentials

- Keep CA, certificate hostname and optional SPKI pin verification **enabled**.
- Treat \`connection.txt\` as a secret. Rotate credentials if exposed.
- Keep the unauthenticated local SOCKS listener on \`127.0.0.1:1080\`.
- Do not enable \`--allow-private\` on an exposed public server without strict isolation.
- Configure host firewall, DNS and fail-closed routing separately if attempting whole-device interception.
- Neither local throughput measurements nor matched HTTP/2 settings prove production stability or DPI resistance.
