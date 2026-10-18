# Streaming XHTTP and Mozilla NSS

[Русский](XHTTP.md) | **English**

FoxTunnel now includes independent `xhttp-stream-one` and `xhttp-stream-up`
carriers. No Xray executable or code dependency is required. Mozilla NSS can
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

Setup produces a private `vetroff://` link with a random access secret, verified
SNI, an additive SPKI pin and the transport. Use `xhttp-stream-one` for a single
duplex POST, or explicitly select `--tls-backend go` without NSS. Upgrade both
ends; the existing H2 POST mode is a different format.

| Mode | Upload | Download |
|---|---|---|
| `xhttp-stream-one` | POST `/.well-known/vetroff-xhttp/` | Same POST's response |
| `xhttp-stream-up` | Streaming POST `/.well-known/vetroff-xhttp/<UUID>` | GET to the same path |

Each channel uses a random UUID. Upload content type is `application/grpc`;
download is `text/event-stream`. These are headers, not gRPC/SSE payload framing.
Requests use random Referer padding; responses use X-Padding (100–1000 bytes).
Responses disable caching/buffering. The otherwise unused stream-up upload
response carries padding every 25 seconds, outside application data. Outer ALPN
is H2 only; H1/H3 carriers are not implemented here.

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

This implements the basic request shape of **two streaming XHTTP modes**.
Packet-up, XMUX, custom path/HTTP Host, different upload/download endpoints and
cross-implementation tests remain pending. Payloads are FoxTunnel, not VLESS;
full Xray XHTTP interoperability is not claimed. Local transfer, TLS rejection,
setup/link, cancellation, admission, discovery and lost-ACK/node-failure tests
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
