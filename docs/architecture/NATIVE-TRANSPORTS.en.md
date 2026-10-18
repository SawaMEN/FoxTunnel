# Native transports without Xray

[Русский](NATIVE-TRANSPORTS.md) | **English**

FoxTunnel implements and terminates seven transports itself. No Xray, sing-box,
external SOCKS carrier or separate protocol client is required. The Go WebSocket
and QUIC dependencies are compiled into the binary.

| `transport` | Outer connection | Client TLS | Discovery and node bonding |
|---|---|---|---|
| `h2-connect` | TLS 1.3 / HTTP/2 CONNECT | Go or experimental NSS | Yes |
| `h2-post` | TLS 1.3 / duplex HTTP/2 POST | Go or experimental NSS | Yes |
| `wss` | TLS 1.3 / HTTP/1.1 WebSocket containing multiplexed HTTP/2 | Go or experimental NSS | Yes |
| `h3-post` | HTTP/3 POST over QUIC/UDP, TLS 1.3 | Go QUIC TLS | Yes |
| `xhttp-stream-one` | Duplex POST carrying FoxTunnel HTTP/2 | Go or experimental NSS | Yes |
| `xhttp-stream-up` | Separate streaming POST/GET with a session UUID, carrying FoxTunnel HTTP/2 | Go or experimental NSS | Yes |
| `xhttp-packet-up` | Numbered POSTs and a streaming GET, carrying FoxTunnel HTTP/2 | Go or experimental NSS | Yes |

Every mode retains CA/hostname verification, additive SPKI pins, authentication,
destination restrictions, cancellation and upload half-close. WSS carries HTTP/2
directly, without nested TLS. It permits 32 concurrent inner streams per connection,
64 KiB incoming messages and 32 KiB outgoing messages; compression is disabled.
`max-tunnels` also bounds outer WSS connections independently of active requests.

H3 is standard QUIC, without Salamander/Gecko or Firefox fingerprint parity.
The client completes TLS before sending HTTP; 0-RTT is disabled. Headers, streams
and receive windows are bounded. `max-connections` separately caps QUIC connections,
including incomplete handshakes. QUIC Retry starts at half capacity. The limit is
independent of TCP admission. This transports application TCP, not SOCKS UDP or TUN.

## Automatic setup

For native WSS with an experimental NSS client:

```sh
./foxtunnel setup --server https://main.example \
  --cert /etc/certs/main/fullchain.pem --key /etc/certs/main/key.pem \
  --transport wss --tls-backend nss --out main-node
./foxtunnel server --config main-node/server.json
./foxtunnel client --link-file main-node/connection.txt
```

That client requires a Linux `-tags nss` build and NSS/NSPR. A normal Go binary
supports WSS with `--tls-backend go`. The server does not require NSS. WSS uses
outer ALPN `http/1.1`; direct H2 modes require `h2`.

For QUIC use `--transport h3-post --tls-backend go`. Setup adds
`"h3_listen": ":443"` to server.json. H3 also requires UDP 443 through the
server firewall and client network; TCP modes require TCP 443. Joining with
`--join-link-file` preserves the main profile's transport and enables the
ingress UDP listener for H3. Ingress-to-hub connections currently remain H2/TLS,
so the hub must still be reachable over TCP. Every advertised ingress must
support the selected client transport. Register nodes using `cluster-add`.

Manual servers can enable UDP with `server --h3-listen :443` alongside their
usual certificate, key and TCP listener settings. Certificate issuance/renewal,
DNS and firewall changes remain administrator tasks.

## Profiles and chains

`client --transport …` selects a mode with manual connection settings;
`share --transport …` exports it as `transport` in `vetroff://`. Imported links
select their own mode and cannot be mixed with connection flags. Missing fields
in old links select `h2-connect`; older clients reject the new unknown field.
Per-origin SNI and pin policies retain their existing scope.

Modes are explicit. Verification, authentication and negotiation failures do not
trigger transport downgrades. Trusted-node failover operates within the chosen
mode. Automatic transport probing and speed-based selection are not implemented.

Native chains now include FoxTunnel over H2 POST/TLS, HTTP/2 over WSS/TLS, and
H3 POST/QUIC. Their framing and authentication are FoxTunnel's. These POST
transports are **not interoperable Xray XHTTP implementations**. Independent `xhttp-stream-one`, `xhttp-stream-up` and `xhttp-packet-up` carriers
now implement the basic XHTTP request shapes. The payload remains FoxTunnel, not VLESS.
They support NSS, setup, links, discovery and bonding. XMUX and cross-implementation interoperability tests are still pending;
full XHTTP compatibility is not claimed. See [XHTTP and NSS](XHTTP.en.md).

Native REALITY, ECH, gRPC, HTTPUpgrade, dnstt, Salamander/Gecko and AWG remain
unimplemented. Researching them does not implement their wire formats. ECH
requires matching keys and server support; QUIC obfuscation stops being standard
HTTP/3. Combining formats or merely changing SNI does not reproduce a browser.

## Evidence and deployment limits

Local tests cover large transfers, half-close, cancellation, rejection of wrong
CA/SNI/pin before HTTP, discovery, two bonded ingresses, lost ACKs, deduplication
and path failure. WSS/H2 POST also have NSS tests. This is not evidence of TSPU
reachability across Russian operators.

- UDP filtering prevents H3; TCP modes remain separate options.
- WebSocket frontends require explicit testing of authentication forwarding,
  timeouts and limits. Arbitrary CDN compatibility is not claimed.
- Duplex POST requires unbuffered requests and responses through a reverse proxy.
- TLS hides HTTP from the transit network, but IP, timing, sizes and clear SNI
  remain observable. TLS terminators see HTTP and must be trusted as ingresses.
- NSS is not full Firefox. Go HTTP behavior, QUIC fingerprint and padding need
  independent measurements.

Russian field testing must record versions, connection success, p50/p95 setup,
useful throughput, loss/recovery, CPU/RAM and observable behavior. No mode is
established as fastest or undetectable.

## Primary sources and versions

- [XHTTP developer description](https://github.com/XTLS/Xray-core/discussions/4113)
  and [transport configuration](https://xtls.github.io/config/transport.html).
  Xray snapshot `92ccc939aaf4f8965f369cf0b142e005aeaa11d5` (v26.10.17) was
  reviewed only; it is not a runtime dependency.
- [coder/websocket](https://github.com/coder/websocket), dependency `v1.8.15`.
- [quic-go HTTP/3 client](https://quic-go.net/docs/http3/client/) and
  [server](https://quic-go.net/docs/http3/server/), dependency `v0.64.0`.
- [Hysteria ECH](https://v2.hysteria.network/docs/advanced/ECH/) and
  [protocol](https://v2.hysteria.network/docs/developers/Protocol/) inform future
  independent work; compatibility is not implemented.

## Local throughput comparison

One established SOCKS stream, 1 MiB echo blocks, Go TLS, no padding or bond,
Linux amd64 / AMD EPYC 9V74, Go 1.26.9. Two short 300 ms runs:
`go test ./internal/tunnel -run '^$' -bench 'BenchmarkNativeTransports/.*/1MiB' -benchtime=300ms -count=2`.

| Mode | Useful MB/s | Allocations per 1 MiB |
|---|---:|---:|
| H2 CONNECT | 266–334 | 641–662 |
| H2 POST | 315–331 | 636–646 |
| WSS | 145–165 | 4313–4656 |
| H3 POST | 184–196 | 9002–9026 |

These short, noisy loopback measurements are not Internet results, Mbit/s or
proof of superiority. Useful payload is counted once per full echo round trip.
WSS and QUIC add framing/packet work. Loss and latency may change the ranking;
Russian deployment choices require actual field measurements.
