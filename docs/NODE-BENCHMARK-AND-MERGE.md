# Node performance: stage 5/5 benchmark and merge gates

Stage 5 adds `--bond-autotune` and reproducible benchmark targets. It
**does not** prove lower latency or more bandwidth on the internet.

## Safe auto-tune

Use `--bond --bond-adaptive --bond-autotune --bond-pipeline auto`.
The scheduler starts with four in-flight blocks, and retains the existing
memory/window ceilings. After at least three recent acknowledged upload
samples and a fresh operation-latency estimate, it computes a conservative
approximate bandwidth-delay product (BDP) across available paths.
It selects eight slots only when that estimate exceeds five 32-KiB blocks.
Short flows, stale samples, path errors and network transitions use four.

`--bond-pipeline 4` and `--bond-pipeline 8` remain explicit overrides.
The option is local: it does not change `vetroff://` or the wire format;
it cannot run without `--bond-adaptive`.
An automatic increase does not revoke already reserved work; a decrease
affects future dispatches only.

**Limits:** The measured rate is HTTP ACK goodput, not spare network
capacity. Delayed application ACKs and shared bottlenecks can distort
the BDP estimate. This is a conservative heuristic, not congestion control,
MPQUIC, or a guarantee against head-of-line blocking.

## Reproducible CPU/allocation benchmarks

Run against the `main` baseline and this branch on the **same runner**,
with the same Go version and build tags:

```sh
go test ./internal/bond -run '^$' -bench 'BenchmarkBond(PathSelection|SkewAndQueue)' \
  -benchmem -benchtime=1s -count=5
go test -race ./internal/bond ./internal/nodeperf ./internal/multihop ./internal/tunnel
go test ./...
go vet ./...
```

`BenchmarkBondPathSelection` measures the overhead of legacy, adaptive,
and smart+adaptive *selection*, not Mbps over a remote server.
`BenchmarkBondSkewAndQueue` covers equal paths, 10× bandwidth skew,
and four-block queued load without sleeping. These microbenchmarks do not
simulate TCP congestion, ISP shaping or a remote relay.

## WAN comparison matrix and gating

For real deployment validation, run each combination with unchanged origin
servers and TLS settings, and repeat across at least three independent days:

| Variant | What to compare |
|---|---|
| Direct single-node CONNECT | Ground-truth single-hop baseline |
| Legacy Bond (pipeline auto) | Existing multipath cost |
| Adaptive Bond, no autotune | Goodput-aware routing effects |
| Adaptive Bond + autotune | BDP gate and queue effects |
| Smart direct+relay + adaptive | Benefit of independent relay topology |

For each scenario vary one-way delay 10/40/100 ms, loss 0/0.5/2%, unequal
bandwidths, 10× skew, and a failing ingress; use `tc netem` only on
isolated test interfaces. Record measured one-way/RTT distributions separately
from HTTP exchange time. Include 1-KiB interactive exchanges and 1/32/256-MiB
transfers, throughput, p50/p95/p99 completion time, CPU, RSS, retries,
recoveries, connection survival and replay safety.

**Proposed acceptance gates** (not results):
- 0 corrupted/duplicated/out-of-order bytes and 0 new TLS/identity bypasses.
- Existing CI, race checks, static checks and existing UDP/TUN suites pass.
- No default performance or memory regression with feature flags off.
- At least 5 repetitions/scenario; inspect confidence intervals. Do not
  enable autotune by default solely from microbenchmarks.
- For optional field rollout, reject scenarios with >10% p95 latency or
  >10% goodput regression against legacy unless explicitly justified.
- Abort any merge if new `main` changes conflict with UDP/TUN/Go SDK tests.

## Integration note

The branch `node` branched before the new experimental UDP/TUN feature
and the docs/release reorganization in `main`. A merge candidate should
start from **current main**, port only node-specific code/tests and preserve
new documentation and dependencies. Prepare a draft PR; do not merge until
required checks and WAN tests are evaluated.
