# Stage 10: bounded optimization evidence

Stage 8 integrations remain deferred. This branch builds on stage 9 PR #44.
The optimization preserves selection order, cooldowns, exploration and dwell
semantics. `multihop.Select` uses local eight-element index buffers; inputs
above eight retain heap-backed storage. No shared scratch buffer or pool is used.

## Paired scheduler gate

`stage10-optimization.yml` builds the same benchmark source against the PR base
and candidate. The benchmark source is copied into the detached base worktree;
the base identity refers to production source and the separately recorded
benchmark hash identifies the injected measurement source. Compilation and
profiles are outside the timed comparison. Both binaries run serially on one
runner, one Go toolchain, `-test.cpu=1`, with a discarded warm-up and seven
alternating base/head repetitions of 250 ms per case. Nothing runs under race
instrumentation during the benchmark. Race tests run separately beforehand.

The complete inventory contains 2, 8 and 16 candidates, each fresh, cold and
in cooldown. Time is fixed inside the scheduler to prevent metric expiry.
The report retains raw logs, their hashes, per-case samples, executable hashes,
compiler metadata and source commits. CPU profiles cover the eight-node fresh
case. These are selection microbenchmarks, not payload, FFI or WAN benchmarks.

Budgets fixed before CI measurement:

| Metric | Requirement |
|---|---|
| Median ns/decision | Candidate/base at most 1.25 |
| Median bytes/decision | No increase |
| Median allocations/decision | No increase |
| Median absolute deviation / median | At most 0.15 on each side |
| Inventory | Exactly 9 cases and 7 repetitions on each side |

Malformed, missing, duplicate, failed or non-finite observations fail closed.
A noisy sample fails the gate and remains in the retained report; rerunning a
noisy CI is permitted, changing thresholds to conceal a result is not.
The 25% CPU budget is deliberately broad for shared runners. It cannot detect
all smaller regressions and is not a statistical significance claim.

## Sustained connections and resources

The new test holds one destination connection per H2/H3 carrier, alternating
64-byte and 32-KiB verified echoes for 600 seconds in CI. It checks the destination
was opened exactly once, then aborts the application socket and requires its
release within five seconds. Ordinary unit runs last two seconds and do not
count as long-run evidence. The subtests run concurrently. A separate 600-second
native CLI workload exercises three concurrent exchanges per carrier, sampled
RSS/descriptor budgets and same-client recovery after a server restart.
Its defaults are peak RSS 512 MiB, RSS growth 192 MiB and descriptors/handles
as enforced by `operations_soak.py`; the report records effective budgets.
Neither test is a multi-day soak or a proof of absence of native leaks.

Routing validation repeats multihop/Bond/node tests five times under the race
detector and repeats actual Bond and UDP multi-node tunnel tests three times.
Native NSS/Neqo transport measurements remain in their existing workflow and
are outside this scheduler gate. Stage 10 completion requires retained new CI
reports; earlier stage measurements are not reused as fresh evidence.

## Reproduce

Use Go 1.26.10. Build `go test -c ./internal/multihop` in base and candidate
worktrees with identical `benchmark_stage10_test.go`, then run:

```sh
python3 scripts/optimization_gate.py --base /tmp/base.test --head /tmp/head.test \
  --base-commit BASE_FULL_SHA --head-commit HEAD_FULL_SHA --out /tmp/paired.json
FOXTUNNEL_LONG_STREAM_SECONDS=600 go test -race ./internal/tunnel \
  -run '^TestStage10LongLivedH2H3$' -count=1 -timeout=12m
```

The report destination must not already exist. The workflow retains reports
and profiles even when a subsequent gate fails. Review the full workflow
conclusion as well as the paired benchmark result.
