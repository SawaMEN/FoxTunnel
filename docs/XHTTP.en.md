# XHTTP and Mozilla NSS

[Русский](XHTTP.md) | **English**

FoxTunnel includes independent `xhttp-stream-one`, `xhttp-stream-up` and
`xhttp-packet-up` carriers. No Xray executable or code dependency is required. Mozilla NSS can
supply client TLS; Go supplies HTTP/2 and server TLS. This does not reproduce
the complete Firefox fingerprint. There is no nested TLS inside the carrier.

```sh
# Client requires Linux, NSS/NSPR, cgo and a -tags nss build.
./foxtunnel setup --server https://main.example \
  --cert /etc/certs/main/fullchain.pem --key /etc/certs/main/key.pem \
  --transport xhttp-stream-up --tls-backend nss --out main-node
./foxtunnel server --config main-node/server.json
./foxtunnel client --link-file main-node/connection.txt
```

Setup produces a private `vetroff://` link with a random access secret, an independent
random `/api/<nonce>/` route, verified
SNI, an additive SPKI pin and the transport. Use `xhttp-stream-one` for a single
duplex POST, `xhttp-packet-up` for packet upload, or explicitly select `--tls-backend go` without NSS. Upgrade both
ends; the existing H2 POST mode is a different format.

## Path, HTTP Host and SNI

Add `--xhttp-path /api/relay-v1 --xhttp-host route.example` to setup for a custom
route. Paths gain a trailing slash. New XHTTP clusters get a random route when
no path is supplied; joined/legacy profiles keep their existing route. Manual
share/client commands still default to the built-in route.

Host affects only outer HTTP Host / H2 `:authority`, not the dial endpoint,
TLS SNI, certificate name or SPKI pin. It defaults to verified SNI if configured,
otherwise the endpoint host. Ports and IPs (bracketed IPv6) are accepted; the
server compares case-insensitively but retains port significance. Host changes
do not themselves enable domain fronting; the frontend must support the route.

Fields `xhttp_path` / `xhttp_host` persist in links and server.json. Join inherits
the cluster route and rejects conflicting overrides. All ingresses must support
the same route; TLS policies remain independent per node. Manually registered
nodes must be configured accordingly. Manual servers accept the same flags.
Upgrade both ends before using the new fields.

The path validator rejects percent encoding, query/fragment, empty or dot
segments, backslashes, spaces and control characters. Host rejects URLs,
credentials, CR/LF and invalid ports. XHTTP settings on another transport fail
rather than being ignored. Wrong Host/path/authentication uses the public site
with proxy credentials removed; the path is not authentication.

Tests cover all three modes through a controlled HTTPS reverse proxy with an
H2 backend and explicit forwarding of hop-by-hop Proxy-Authorization. Frontends
must stream bodies/responses without buffering. This does not establish arbitrary
CDN compatibility or Russian reachability.

| Mode | Upload | Download |
|---|---|---|
| `xhttp-stream-one` | POST `/.well-known/vetroff-xhttp/` | Same POST's response |
| `xhttp-stream-up` | Streaming POST `/.well-known/vetroff-xhttp/<UUID>` | GET to the same path |
| `xhttp-packet-up` | POST `/.well-known/vetroff-xhttp/<UUID>/<seq>` | GET without seq |

Each channel uses a random UUID. Streaming upload content type is `application/grpc`;
download is `text/event-stream`. These are headers, not gRPC/SSE payload framing.
Requests use random Referer padding; responses use X-Padding (100–1000 bytes).
Responses disable caching/buffering. The otherwise unused stream-up upload
response carries padding every 25 seconds, outside application data. Outer ALPN
is H2 only; H1/H3 carriers are not implemented here.

Packet-up uses fixed-length `application/octet-stream` POSTs, up to 32 KiB from
the client, with at most four unacknowledged sequence positions (128 KiB of
client payload buffers per carrier). The next POST starts only after the previous
body is completely written, without waiting for its response. ACKs follow ordered
delivery; only contiguous ACKs advance the window. Early responses cannot release
an upload buffer, and ambiguous failures close the carrier without HTTP replay.
The four-request cap still limits throughput at high RTT; transport/header buffers
are additional to the payload budget. The server reserves at most eight
blocks of up to 64 KiB, including reads in progress and a blocked delivery.
It reconstructs numbered blocks from zero, rejects duplicates, out-of-window
numbers and stream/packet mixing. A missing sequence or stalled body expires
after 30 seconds; successful delivery resets the gap deadline. Lost/failed ACKs
close the carrier rather than replaying accepted bytes. Bond RPC recovery
remains the responsibility of FoxTunnel's session layer.

The carrier contains multiplexed FoxTunnel HTTP/2, including discovery and bond,
with 32 concurrent inner streams. Authentication precedes state allocation and
is checked again on inner requests. Rejected probes use the public cover handler.
Like WSS, this requires a reverse proxy to retain `Proxy-Authorization`.
CA/hostname and pin verification precede HTTP credentials, including with NSS.

External sessions have a separate `max-tunnels` limit (default 256). Unpaired
requests expire after 30 seconds; duplicate sides are rejected. Pipes provide
backpressure instead of unbounded queues. Cancelling either request tears down
both directions and the inner session. Idle close retires carriers once their
active inner bodies finish, without cutting off active streams.

This implements the basic request shapes of **three XHTTP modes**.
XMUX, different upload/download endpoints and
cross-implementation tests remain pending. Payloads are FoxTunnel, not VLESS;
full Xray XHTTP interoperability is not claimed. Local transfer, TLS rejection,
setup/link, cancellation, admission, packet size/order/replay/gap/ACK failure, discovery and lost-ACK/node-failure tests
are not evidence of CDN or Russian operator reachability.

Sources: [XHTTP developer description](https://github.com/XTLS/Xray-core/discussions/4113)
and [reference server](https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/hub.go).

## Short loopback measurement

Go 1.26.9, Linux amd64 / AMD EPYC 9V74, Go TLS, one established SOCKS stream,
1 MiB echo without bond/padding, two 300 ms runs:

| Mode | Useful MB/s | Allocations/op |
|---|---:|---:|
| H2 CONNECT | 257–308 | 614–616 |
| XHTTP stream-one | 145–183 | 1860–1882 |
| XHTTP stream-up | 202–203 | 1832–1846 |

Command: `go test ./internal/tunnel -run '^$' -bench 'BenchmarkNativeTransports/(h2-connect|xhttp)/1MiB' -benchtime=300ms -count=2`.
Nested H2 adds overhead here; this is not an improvement over CONNECT. These
short loopback runs do not measure Internet routes, NSS or Russian networks.

A fresh before/after test of the bounded packet-up pipeline (Go 1.26.9, same host,
1 MiB SOCKS/inner-H2 echo, 500 ms, two runs) measured 38.44–42.78 →
95.84–96.13 MB/s. Bytes allocated per exchange fell from 5.16–5.33 to 3.69–3.87 MB;
allocation count increased from about 17.4k to 19.8–20.0k. Historical shorter runs
were noisy and are not directly comparable to this before/after pair.

The separate carrier-only benchmark isolates ACK delay, not complete Internet
RTT: `go test ./internal/xhttp -run '^$' -bench BenchmarkPacketWindow -benchtime=500ms -count=2`.
With a 256 KiB echo and a 40 ms response delay per POST, window 1 measured
0.80 MB/s and window 4 measured 3.18 MB/s; with no artificial delay, 100.5–110.2
and 169.7–177.1 MB/s respectively. The fixture does not add loss, TCP delay or a
throughput cap. Write coalescing and persistent bond channels remain separate
work. These local Go TLS measurements do not establish NSS, Internet or TSPU
performance. [Live Firefox TLS/H2 profiles](WEB-PROFILE.en.md) measure a different
question: the current transports still differ from a browser.
