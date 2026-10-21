# Adaptive Bonding — stage 2: traffic-aware scheduling

> Historical development/measurement record. Current supported TCP Bond status: [XHTTP/Bond stability contract](XHTTP-BOND-STABILITY.md). Performance/default-rollout claims still require their own measurements.

[Node guide](NODES.md) · [Stage 1](ADAPTIVE-BONDING-STAGE1.md) ·
[WAN benchmark and merge gates](NODE-BENCHMARK-AND-MERGE.md)

## Objective

Prefer low completed-HTTP-operation latency for the beginning of a stream
and small application writes, while selecting high-ACKed-throughput routes
for large transfers. This is a **local TCP Bond ingress scheduling** policy,
not a replacement for kernel routing, true multipath TCP, congestion
control, packet-level load balancing, or UDP game traffic.

### Implementation

- A single, explicitly configured `--bond-traffic` mode:
  `legacy` (default), `latency`, `throughput`, or `auto`.
- `auto`: before 128 KiB of accepted upload or consumed download, choose
  the lower-latency path (accounting for queued work). After that threshold,
  use the existing Adaptive Bond goodput scheduler for full-size blocks.
  Small (<4 KiB) uploads continue to prefer lower latency.
- `latency`: use successful HTTP operation time rather than inferred
  physical RTT; avoid queued and cooling ingress paths.
- `throughput`: use the existing measured ACKed upload/download throughput.
- New state is local to a `bond.Stream` and only counts bytes. The server,
  TLS, authentication, cluster identity, ACK deduplication, and wire format
  are unchanged. Legacy clients and profiles remain compatible.
- Unknown paths can be sampled only by a bounded fraction of real work;
  no extra ICMP, DNS, or out-of-band probes are generated.

### Validation

```sh
go test ./internal/bond -run 'Test(Traffic|Adaptive)' -count=3
go test ./internal/tunnel -run 'Test(BondTraffic|DiscoveredBondTraffic)'
go test -race ./internal/bond ./internal/tunnel ./internal/nodeperf ./internal/multihop
go test ./...
go vet ./...
```

The test harness includes deterministic selection/cooldown cases, mode
validation, an unchanged common hub destination and multiple HTTP/2
ingress servers. Passing them proves stream correctness under tested
conditions, **not** higher throughput or reduced ping on independent VDS.

For independent WAN testing, compare single hub, legacy Bond, latency,
throughput and auto using the same VDS links, origin, TLS settings and
repetitions. Report 1 KiB request completion time (p50/p95/p99), 32/256
MiB goodput, per-ingress work, CPU, memory and failure recovery. Keep
slow-path and fast-path traffic independent where possible. Reject a
>10% p95 latency or goodput regression unless explicitly explained and
documented.

### Limits and safety

- Setting `--bond-traffic` is opt-in and requires `--bond --bond-adaptive`.
- Using `--bond-route smart` also requires trusted discovery and a direct
  route to the pinned authenticated hub.
- No application payload inspection or automatic game recognition.
- No UDP/TUN bonding or Multi-Exit. The shared hub can be a bottleneck.
- The mode cannot reduce propagation delay below the fastest usable route.
- Do not merge to production or claim a performance gain without full CI,
  Go race checks and reproducible external WAN comparisons.
