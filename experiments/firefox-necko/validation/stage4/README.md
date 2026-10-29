# Stage 4 operational qualification

Target: the separate Linux amd64 Necko launcher on Ubuntu 24.04. This record
qualifies the controlled fixtures below; it does not qualify every deployment
network or merge Necko into the ordinary Vetroff CLI/SDK.

## Runtime identity

The native source build [39952039057](https://github.com/SawaMEN/VetroffProxy/actions/runs/39952039057)
passed on `cb5c2f08d99005377efd2fcdedd4f4a2faaaa777`. Its runtime artifact is
`12501945687`. [runtime-provenance.json](runtime-provenance.json) records the
exact source lock and four binary SHA-256 hashes. Each consuming CI run compares
that lock and those hashes before running tests. The build provenance status
`built-not-interop-tested` describes compilation; acceptance is established by
the separate test results, not that build status.

The initial packaged-runtime run
[39952847618](https://github.com/SawaMEN/VetroffProxy/actions/runs/39952847618)
passed at `7e00f47b19378b00cbdc1b5caeeec4657e3d2154`, with the same native lock.
Its complete [workflow log](ci-60s/workflow.txt) and minute-long resource samples
are retained under `ci-60s/`.

## Gates

- Native CONNECT, binary transfer, directional EOF, restricted flow control,
  trust checks before authentication, concurrent streams and cancellation.
- Full Firefox versus helper wire comparison, three repetitions per protocol.
- Idle expiry and bounded native drains, admission rejection at the retained
  session limit, then slot recovery; three repetitions.
- Controlled path interruption, bounded failure and a new CONNECT after path
  restoration in the same helper. No application-stream replay.
- H3 source-port rebinding with binary transfer on the existing application
  stream. The client-facing proxy address stays fixed.
- Immutable bundle generation, source/helper compatibility, all-file digest
  verification, corruption/missing/extra-file and symlink rejection.
- Actual packaged launcher, unrelated working directory, H2/H3 binary transfer,
  SIGTERM, listener shutdown and private-profile removal.

## Resource method

Each protocol gets a fresh helper and 16 verified warmup tunnels. The measured
load repeatedly starts eight concurrent 128 KiB binary transfers with half-close
and exact returned bytes, then pauses 100 ms between batches. `/proc` measurements
cover the helper process only, excluding the Go proxy and fixture. CPU units use
host `CLK_TCK`; percentages may exceed 100 on multiple cores.

The regression gate compares the warmed baseline with the drained end:
FD growth must be at most 32 and RSS growth at most 192 MiB. Intermediate samples
are preserved. It also requires exact upload/download counters, zero idle
expirations, zero refusals and no remaining active or retained sessions.
The payload is transferred in both directions; reported rounds exclude warmup.
These checks measure bounded churn, not maximum throughput or multi-day stability.

The first 60-second run passed:

| Transport | Verified rounds | RSS, KiB | FDs | Helper CPU, seconds |
| --- | ---: | ---: | ---: | ---: |
| H2 | 1896 | 136840 → 119036 | 45 → 45 | 39.64 |
| H3 | 1744 | 138392 → 122016 | 45 → 45 | 75.22 |

The first 300-second-per-protocol run
[39988655835](https://github.com/SawaMEN/VetroffProxy/actions/runs/39988655835)
failed the unchanged RSS-growth gate: H2 grew from 129000 to 489792 KiB,
H3 from 136628 to 395464 KiB. All bytes, tunnel counters and descriptor
counts passed. Samples and logs are preserved under `regression-212c2ac/`.
Reading directly into bounded ArrayBuffers and releasing retired session
references alone did not fix reclamation: the local 60-second H2 trial still
failed (114152 → 378788 KiB). Both protocol samples are in `regression-buffer/`.

The helper now also collects retired JS/XPCOM work after at least 64 retirements,
at most once per five seconds, using GC/CC/GC. It leaves live streams rooted and
does not send a memory-pressure notification or clear HTTP/TLS caches. Its
`gc_collections` and `gc_ms` counters make the actual maintenance observable;
CPU measurements include its cost. This runs in the product helper, not as a
measurement-only cleanup in the test.
The local minute-long regression run with this maintenance passed on the exact
same four compiled runtime hashes. H2 completed 2368 rounds with RSS
116124 → 117328 KiB; H3 completed 2312 rounds with RSS 123064 → 121856 KiB.
Both retained 40 FDs. Twelve collections took 178 ms in H2 and 231 ms in H3
in total; process CPU was 33.26 and 59.12 seconds, respectively. Full measurements
are retained in `local-60s/`. This is evidence of the fix, not a throughput ranking.

The final repeated qualification passed in
[39991403260](https://github.com/SawaMEN/VetroffProxy/actions/runs/39991403260)
on helper `eb92e13637a49a38013d97098209acfe59de99f5`, including native gates,
network recovery and the actual packaged launcher after the load.

| Transport | Verified rounds | RSS, KiB | FDs | Helper CPU, seconds |
| --- | ---: | ---: | ---: | ---: |
| h2-connect | 14384 | 121544 → 200088 | 45 → 45 | 136.62 |
| h3-connect | 13456 | 131040 → 279276 | 45 → 45 | 244.67 |

All samples, the complete workflow log and CI step/artifact metadata are retained
under `ci-300s/`. [acceptance.json](acceptance.json) binds the code, native build,
source/helper/binary hashes, artifacts and results.

The independent local clean-bundle verification and actual packaged H2/H3,
SIGTERM, listener and profile cleanup tests also passed. An earlier local copy
was correctly rejected for extra temporary files next to libxul; the accepted
local package was assembled from a fresh source archive in a separate directory.

Download the [qualified Linux amd64 bundle](https://github.com/SawaMEN/VetroffProxy/actions/runs/39991403260/artifacts/12519391254).
Its `.tar.gz` SHA-256 is:

```text
808a968d76758fc595da5ff758617e12aba2f84398855071f0434bf92a85e024
```

The outer GitHub artifact ZIP has a separate digest in `acceptance.json`.
The artifact expires on 2026-11-06; retain your verified archive for rollback.

## Independent local five-minute run

The same compiled runtime hashes and helper `eb92e13` passed a second,
independent 300-second run per protocol on Linux 6.18.55 x86_64 with Go 1.26.10
and the race detector. The [test log](local-300s/test.txt) and complete sampled
measurements are retained under `local-300s/`.

| Transport | Verified rounds | RSS, KiB | FDs | Helper CPU, seconds |
| --- | ---: | ---: | ---: | ---: |
| h2-connect | 11896 | 116284 → 223548 | 40 → 40 | 165.07 |
| h3-connect | 11280 | 120612 → 137012 | 40 → 40 | 298.35 |

GC/CC/GC ran 57 times for H2 (966 ms total) and 58 times for H3 (1283 ms total).
The maximum *sampled* RSS was 330736 KiB and 307872 KiB, respectively. These
are batch samples, not a continuous peak-memory trace. The acceptance RSS gate
uses the drained end, not the sampled maximum. Counters matched every transferred
byte and no sessions, retained drains, refusals or idle expirations remained.

## Repeated Firefox comparison

The [first repeated comparison](regression-212c2ac/fingerprint/comparison.json) and its six
observations are retained for the current source lock. TLS/ALPN and H2 SETTINGS
matched in all three H2 repetitions. One repetition had different raw HPACK
blocks and HEADERS lengths on the first connection: Firefox used 98 then 8
bytes; the helper used 101 then 5. The decoded header fields agreed. The other
two H2 repetitions had no measured differences. This record does not infer a
cause or normalize away the raw encoding difference.

All three H3 repetitions retained different extension order/JA3, while extension
sets and the other measured fields agreed. Each subject had three distinct H3
extension orders and one extension set. These observations qualify the historical
stage 3 agreement: exact byte-for-byte wire equality is not an acceptance claim.
The [final helper comparison](ci-300s/fingerprint/comparison.json), also with six
observations, retained the same kinds of difference: two of three H2 repetitions
had raw HPACK/HEADERS-size differences and different SETTINGS ACK ordering
relative to the first HEADERS/WINDOW_UPDATE, with identical decoded fields. Every
H3 repetition had randomized extension-order/JA3 differences. TLS/ALPN, H2
SETTINGS, H3 extension sets and the other retained fields agreed.

The comparator checks complete, consistent observations and preserves differences;
a successful comparison step means valid evidence was collected, not that every
field matched.

## Native regressions fixed during qualification

Abort and timeout paths exposed main-thread calls into socket-owned H2/H3
transport state. Both native `Close` implementations now dispatch to the socket
thread before touching that state.

H2 churn then exhausted the per-host connection pool: the bootstrap transaction
retained an empty connection handle after raw CONNECT handoff. The successful
H2 handoff now releases that handle. The actual H2 stream still owns its session
and native concurrency slot. Idle recovery and repeated churn exercise this fix.

Clean JS pump completion still permits queued native bytes to drain. The helper
retains these transports within a configured budget and deadline; it never
force-closes them at JS completion, which previously truncated tails.

## Distribution and limits

See [OPERATIONS.md](../../OPERATIONS.md) for configuration, immutable version
directories, checksum verification, update/rollback and test reproduction.
The CI `vetroff-necko-linux-amd64` artifact includes the full runtime, launcher,
source lock/provenance, native patches, license notices and `SHA256SUMS`.
Artifacts expire; retain a verified archive for deployment and rollback.

The controlled network fixture does not simulate proxy IP changes, IPv4/IPv6
switching, mobile-operator handoff or Internet packet-loss distributions.
Those cases and multi-day reliability need a deployment-specific pilot. The
Firefox comparison uses the same native CONNECT API, not ordinary page navigation;
it establishes neither packet-shape parity nor DPI indistinguishability.
