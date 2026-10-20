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

## Compatibility

The main branch now also contains experimental UDP and Linux TUN.
Those features are **not** compatible with Bonding today; this
node-routing work preserves existing UDP/TUN behavior and does not
implement Bonding for application UDP.

Before making the optional features defaults or deploying them in
sensitive environments, review the
[benchmark matrix and safety gates](NODE-BENCHMARK-AND-MERGE.md),
run full CI and compare real paths and independent VDS links.
