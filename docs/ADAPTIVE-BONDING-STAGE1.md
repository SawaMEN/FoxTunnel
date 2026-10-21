# Adaptive Bonding: stage 1 (baseline and safe scheduling)

> Historical development/measurement record. Current supported TCP Bond status: [XHTTP/Bond stability contract](XHTTP-BOND-STABILITY.md). Performance/default-rollout claims still require their own measurements.

[Node configuration](NODES.md) · [Benchmark gates](NODE-BENCHMARK-AND-MERGE.md)

## Objective and boundaries

Stage 1 reduces the work performed for **each Adaptive Bonding block
decision**, establishes a reproducible two-ingress HTTP/2 integrity test,
and records isolated scheduler benchmarks on CI.

This is **not proof** that traffic across multiple independent VDS
connections is faster or has lower network RTT. There are no new
transports, protocol messages, encryption modes, route discovery rules,
UDP Bonding, or automatically enabled flags.

The measured Adaptive Bonding rate is ACKed application-block goodput;
full HTTP operation latency includes relay work, remote service delay,
and queuing. Neither value is an ICMP ping or a raw link bandwidth test.

## What changed

- Allocation-free candidate selection in `internal/bond/adaptive.go`.
  It preserves the existing cooldown behavior, minimum-pending fallback,
  measured path preference, and periodic sampling of unknown paths.
- Deterministic eligibility tests covering 2–8 ingress paths, cooling
  paths, tried masks and both upload and download.
- A local HTTP/2 test using two TLS listeners and **one** Bond hub, which
  transfers real stream data, verifies byte-for-byte equality, confirms
  that both ingresses carry upload blocks, and checks for a single
  destination dial.
- Isolated `BenchmarkBondAdaptivePick` (2 and 8 paths) and CI execution
  alongside the existing Bond selection/queue benchmarks.

The integration test deliberately adds small application-level delays so
successful block exchange samples can be collected on fast CI machines.
Those delays do **not** model real packet loss, independent network paths,
ISP traffic shaping, or WAN RTT.

## Repeatable verification

Use the same Go version and build tags for baseline and candidate.

```sh
go test ./internal/bond -run '^TestAdaptive(BondHTTP2MultiIngressIntegrity|Pick)' -count=3 -timeout=120s
go test -race ./internal/bond ./internal/nodeperf ./internal/multihop ./internal/tunnel
go test ./...
go vet ./...
go test ./internal/bond -run '^$' -bench '^BenchmarkBondAdaptivePick$' -benchmem -benchtime=1s -count=5
```

Compare the isolated scheduler CPU cost (`ns/op`) and allocations
(`B/op`, `allocs/op`) on the same runner. Do not infer an application
speedup from this microbenchmark alone.

For actual throughput and latency, follow the full WAN matrix in
[NODE-BENCHMARK-AND-MERGE.md](NODE-BENCHMARK-AND-MERGE.md).
Use real, separately hosted ingresses with the same pinned hub and
realistic slow/fast routes. Measure TCP upload/download goodput,
small-request p50/p95/p99 completion times, retransmissions, recovery,
CPU and RSS. Repeat tests across several days and record baseline
single-node, legacy Bond, adaptive Bond, and adaptive+autotune.

## Enable on a prepared trusted cluster

The connection profile must already include a trusted, discoverable
Bond cluster with a common authenticated hub:

```sh
foxtunnel client --link-file connection.txt \
  --bond-route smart --bond-adaptive --bond-autotune \
  --bond-metrics-interval 10s
```

The flags stay opt-in. The `smart` route requires the hub to be
reachable directly and through a trusted relay. `--bond-adaptive` and
`--balance adaptive` are different schedulers; do not combine them.

**Release gate:** do not turn this feature on by default, merge a
regression, or claim a faster VPN based on local test success. Check CI,
the race detector and the independent WAN measurements first.
