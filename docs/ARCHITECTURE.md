# FoxTunnel technical design

## Baseline data path (implemented)

`application → SOCKS5/TCP loopback → Go HTTP/2 CONNECT client → TLS 1.3 → Go HTTP/2 CONNECT server → TCP destination`

The local inbound supports SOCKS5 `CONNECT` and IPv4/IPv6/domain addresses. A persistent Go `http.Transport` multiplexes HTTP/2 streams over connections. Each connection uses a CONNECT request with `:authority` equal to the target and `Proxy-Authorization` inside the encrypted tunnel. The server resolves and filters the destination IP and relays bytes in both directions, flushing responses for interactive applications. The server's default bind address and the client's local bind address are both loopback.

Ordinary requests and rejected tunnel probes use a shared `Cover` handler, with `Proxy-Authorization` removed. The CLI supports an operator-owned static site using `--web-root`, or a plain 404 if no site is configured. Dotfiles and directory listings without index.html are rejected. This removes the fixed FoxTunnel page; it does not establish active-probing resistance or hide Go TLS/HTTP2 behavior. An independent reverse proxy is not implemented.

The client uses bounded dial/TLS/CONNECT setup, with an explicit setup cancellation timer for streaming CONNECT bodies. That timer is stopped after headers arrive and does not limit stream lifetime. A per-client in-memory TLS session cache enables resumption on reconnects. On the server, filtered and pinned destination IPs are partitioned by family; the second family starts after 250 ms or immediately when the primary family fails. Context cancellation closes losing dials and active destination sockets. Upload EOF is propagated with TCP CloseWrite so response-after-EOF applications remain functional.

## Mozilla/Firefox experiment (not implemented)

Firefox uses NSS for TLS, Necko for networking and Neqo (Rust) for QUIC and HTTP/3. Loading NSS alone cannot guarantee Firefox-like TLS signatures: Firefox manages extension order, ALPN, HTTP/2 configuration, connection reuse and timeout behavior. Necko is not a standalone client library. Our first experiment will characterize real Firefox traces and identify a feasible NSS adapter. Neqo will be evaluated as a separate QUIC/HTTP/3 transport, not swapped into the current Go `http.Transport` without significant engineering.

Important: [`mozilla/neqo`](https://github.com/mozilla/neqo) explicitly marks its server implementation as experimental and unsuitable for production. The baseline uses Go's stable HTTP/2 server instead.

## Non-goals for the current milestone

- Claiming undetectability, indistinguishability from Firefox or better censorship resistance.
- Inventing new cryptographic primitives or bypassing certificate verification.
- Exposing unauthenticated public SOCKS5 endpoints.
- Advertising UDP support before CONNECT-UDP, fragmentation, replay and congestion behavior are implemented.

## Proposed comparative measurements

Capture Firefox and the FoxTunnel client on the same OS for the same origin, transport and Firefox version. Compare TLS ClientHello, JA4-like features, H2 SETTINGS/HEADERS/order, ALPN, QUIC transport parameters, timing, connection lifetimes and application overhead. Evaluate rate of success after the remote IP is blocked separately from classifier accuracy. Publish both successful results and failures.

## Native NSS spike (capture only)

`experiments/nss-clienthello/` uses NSS and NSPR directly to generate a TLS
1.3 ClientHello, allowing measurements with the same metadata probe. It
connects only to loopback; the listener closes before the handshake completes.
This experiment must not be promoted to a transport without a verified certificate
chain and hostname, trust-store management, deadlines, concurrency design and
HTTP/2 framing. Production NSS version pinning remains an open task.
