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
| \`xhttp-stream-one\`, \`xhttp-stream-up\`, \`xhttp-packet-up\` | Stable, explicitly selected XHTTP carriers |

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

## Device VPN integration

The host client owns TUN, its packet stack, routing, DNS and kill switch.
Built-in Linux TUN and system VPN launchers have been removed.
See the [integration contract](INTEGRATION.md).

## Multi-node and access control

Optional cluster ingress, bond streams, fallback servers and managed user quotas are available. Start with a single server. Advanced modes need compatible identities and an operator-maintained cluster configuration. View supported options with \`foxtunnel --help\`, \`foxtunnel server --help\`, and \`foxtunnel access --help\`.

## Security essentials

- Keep CA, certificate hostname and optional SPKI pin verification **enabled**.
- Treat \`connection.txt\` as a secret. Rotate credentials if exposed.
- Keep the unauthenticated local SOCKS listener on \`127.0.0.1:1080\`.
- Do not enable \`--allow-private\` on an exposed public server without strict isolation.
- Configure host firewall, DNS and fail-closed routing separately if attempting whole-device interception.
- Neither local throughput measurements nor matched HTTP/2 settings prove production stability or DPI resistance.

XHTTP and advanced TCP Bond modes have a [supported stability contract](XHTTP-BOND-STABILITY.md), including opt-in configuration, bounded resources, retry and half-close semantics. Their status does not change the Go API or Neqo release policy.
