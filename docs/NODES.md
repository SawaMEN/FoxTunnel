# Node routing and Adaptive Bonding — experimental

[Home](../README.md) · [Features](FEATURES.md) · [Benchmark and merge gates](NODE-BENCHMARK-AND-MERGE.md)

FoxTunnel supports up to eight explicitly trusted HTTPS ingress servers
and a common exit for Bonding. The following settings are **opt-in**.
TLS validation, authentication, the Bond block wire format and server
limits stay unchanged. These features **have not** been validated to
improve latency or throughput across actual networks.

## Ordinary TCP SOCKS5 ingress selection

Use `--balance adaptive` with `--server` and one or more
`--fallback-server` options, or generate a `vetroff://` profile
whose `"balance"` field is `"adaptive"`.

```sh
foxtunnel client --server https://edge-a.example \
  --fallback-server https://edge-b.example --balance adaptive \
  --node-status-interval 10s
```

The scheduler only chooses ingress for **new** TCP connections,
using recent successful HTTP responses (at least three), request
latency, jitter, failures and in-flight work. It avoids frequent
switching and retains the original failover policy for terminal
TLS/HTTP errors. No active ICMP tests or background probes occur.
Response latency is **not** network ping and request failures are
**not** packet loss.

## Bonding with smart direct/relay routing

For a cluster where the coordinator hub itself is an allowed ingress
and at least one trusted relay points to that **same** authenticated
hub, the client can compare real Bond-operation latency for:

- Client → hub → destination
- Client → one trusted relay → same hub → destination

The cluster manifest must list hub and relay, and the existing hub-ID
binding remains enforced. Arbitrary multi-relay chains and separate
exit servers are not supported.

```sh
foxtunnel client --link-file connection.txt --bond-route smart
```

The imported connection must enable Bonding and discovery.
`--balance adaptive` cannot be combined with Bonding, because
its selector applies to ordinary CONNECT only.

## Throughput-aware Adaptive Bonding and AutoTune

```sh
foxtunnel client --link-file connection.txt \
  --bond-route smart --bond-adaptive --bond-autotune \
  --bond-metrics-interval 10s
```

`--bond-adaptive` assigns new ACKed data blocks by measured
application-block throughput and queue depth. It penalizes very
slow paths while keeping bounded fallback and block deduplication.
`--bond-autotune` requires `--bond-adaptive` and adjusts the
existing automatic Bond pipeline conservatively between four and
eight blocks, based on recent upload samples and an approximate BDP.
Manual `--bond-pipeline 4` or `8` remains authoritative. No new
congestion-control protocol is introduced.

`--node-status-interval` and `--bond-metrics-interval` are
optional local-only JSON logs, disabled by default. They can expose
node hostnames, so do not publish logs without reviewing them.

## Stage 2: local interactive/bulk traffic scheduling

With a trusted Bond cluster already configured, `--bond-traffic` opts into
stream-aware TCP ingress scheduling. The four choices are:

- `legacy` (default): unchanged adaptive throughput/queue scheduler.
- `latency`: favor ingress paths with lower successful HTTP exchange time and
  bounded queue depth; this is **not network ICMP ping**.
- `throughput`: prefer successful ACKed data-block throughput and available
  queue headroom, using the existing Adaptive Bonding selector.
- `auto`: favor lower delay at the beginning of each TCP stream, prefer
  measured throughput after at least 128 KiB have been accepted or received,
  and keep individual short writes latency-oriented.

The classifier uses only transferred byte counts and block sizes. It does
**not** inspect TLS contents, identify games, infer a destination application,
or guarantee lower RTT. The class affects only the choice of authenticated
trusted ingress for **new data operations**, never replays or moves an existing
remote TCP destination. No new wire messages or UDP bonding are added.

```sh
foxtunnel client --link-file connection.txt \
  --bond-route smart --bond-adaptive --bond-autotune \
  --bond-traffic auto --bond-metrics-interval 10s
```

`--bond-traffic` requires Bonding and `--bond-adaptive`; it also works with
explicit trusted Bond endpoints without `--bond-route smart`. With smart
routing, the coordinator hub must remain an ingress and each relay must lead
to the **same** authenticated hub. The setting is local and intentionally
absent from `vetroff://` wire profiles: pass it as a client CLI opt-in.

For the tests, limitations, and WAN acceptance criteria, see
[stage 2 validation](ADAPTIVE-BONDING-STAGE2.md).

## Stage 3: independent UDP destination sharding

For the experimental UDP Stream v2 carrier, `--udp-multi-node` splits
**different destinations** across 2–8 explicitly trusted HTTPS origins.
Every destination stays on one exit for the entire UDP association, so
a game flow is never per-packet striped across changing source addresses.

```sh
foxtunnel client --server https://ingress-1.example \
  --fallback-server https://ingress-2.example \
  --enable-udp --udp-stream --udp-multi-node
```

This feature is **separate from TCP Bonding**; it cannot be combined with
`--bond`, `--discover`, or `--tun`. The multi-node session fails closed
if one trusted stream disconnects or refuses UDP v2, with no silent
rerouting of existing UDP flows. It can reduce cross-flow queue blocking,
but does not make a single game session have a lower ping or aggregate
2–8 server bandwidth. Read the [Stage 3 limitations and test plan](ADAPTIVE-BONDING-STAGE3.md).

## Compatibility

The main branch now also contains experimental UDP and Linux TUN.
Those features are **not** compatible with Bonding today; this
node-routing work preserves existing UDP/TUN behavior and does not
implement Bonding for application UDP.

Before making the optional features defaults or deploying them in
sensitive environments, review the
[benchmark matrix and safety gates](NODE-BENCHMARK-AND-MERGE.md),
run full CI and compare real paths and independent VDS links.
