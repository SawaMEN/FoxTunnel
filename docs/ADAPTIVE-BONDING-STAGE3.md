# Stage 3 — UDP flow sharding over trusted HTTPS ingress nodes

[Node routing](NODES.md) ·
[Stage 2 TCP traffic scheduling](ADAPTIVE-BONDING-STAGE2.md) ·
[WAN benchmarking](NODE-BENCHMARK-AND-MERGE.md)

## Experimental scope

UDP Stream v2 now supports an **opt-in multi-node association**. A local
SOCKS5 UDP ASSOCIATE opens one authenticated full-duplex HTTP/2 or HTTP/3
stream to each explicitly configured trusted ingress. Individual UDP
destinations are assigned to exactly one ingress using a stable hash of
destination hostname/IP and port. A single destination's datagrams are never
striped across different exits: doing so could change its NAT source and break
game servers, voice connections or other stateful peers.

Independent destinations can use separate HTTPS streams at the same time,
reducing **cross-flow head-of-line blocking** caused by a slow HTTPS stream
on one node. This is not IP-level bonding, UDP congestion control, FEC,
packet-level duplication, reordered-packet recovery, or a lower physical RTT
guarantee. A single UDP game flow does not gain aggregate speed from the
other exits.

## Usage

Each server must already be configured with the same credentials and its
existing UDP Stream v2 feature enabled:

```sh
FOXTUNNEL_USER=alice FOXTUNNEL_PASSWORD=secret \
  foxtunnel server --enable-udp --cert server.crt --key server.key
```

Client-side, configure **two or more explicit trusted HTTPS origins** with
appropriate TLS certificate verification:

```sh
FOXTUNNEL_USER=alice FOXTUNNEL_PASSWORD=secret \
  foxtunnel client --server https://ingress-1.example \
    --fallback-server https://ingress-2.example \
    --enable-udp --udp-stream --udp-multi-node
```

The feature can use 2–8 explicit trusted servers. It is disabled by
default; `--udp-multi-node` requires `--enable-udp --udp-stream` plus
at least one explicit fallback server, and cannot be combined with
`--bond`, `--discover` or `--tun`. TCP Adaptive Bonding remains a
separate feature. No changes to server wire messages are required.

## Safety and resource bounds

- Every entry is authenticated over verified HTTPS/TLS; no redirects or
  HTTP/1.1 downgrade. Each entry must support UDP Stream v2.
- All entries must be ready before the association starts dispatching.
  Setup has a bounded timeout based on the client connect timeout.
- Packets of one destination remain on its assigned node for the whole
  association. If any stream fails after setup, **the whole association
  closes**, rather than silently moving an active flow to a different NAT
  identity. Applications can establish a new UDP association themselves.
- One bounded 16-datagram queue per ingress. When a queue fills, only
  datagrams destined to that ingress are dropped instead of blocking
  the entire association. UDP remains best-effort.
- SOCKS UDP source address/port pinning and the existing UDP parser,
  message limits and server destination policy remain in effect.
- Additional HTTPS streams consume memory and remote connection capacity.
  Ingresses can have *different* public IPs, which is visible to remote
  targets across distinct flows.

## Validation

```sh
go test ./internal/tunnel -run '^TestUDPMultiNode|^TestUDPIngress' -count=3 -timeout=120s
go test -race ./internal/tunnel -run '^Test(UDP|UDPMultiNode|UDPIngress)' -count=1 -timeout=120s
go test ./... -count=1 -timeout=120s
go vet ./...
```

Integration tests exercise two separate TLS/H2 ingress servers, distinct
UDP destinations, stream loss/refusal, datagram integrity and source pinning.
Synthetic local tests do **not** measure gaming ping or WAN loss/jitter.

On independent VDS, compare one UDP v2 ingress against 2–8 separate
ingresses: per-flow jitter/p50/p95/p99 completion latency, cross-flow
congestion, packet drops, egress IP stability, UDP echo reliability,
memory usage and cancellation under failure. Ensure each server's egress
authorization and destination firewall rules are independently validated.

No performance claims or production defaults should change until real
field data supports them.
