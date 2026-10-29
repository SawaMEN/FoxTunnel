# Stage 2: CLI/SDK and sustained native resources

Status: **qualified — 4 of 4 checks complete**.
Overall plan: **2 of 6 stages complete**. Linux amd64 only.

Qualified helper/SDK code: `b5d86cc2928a0e82066a6b401a9fd83449cca5c9`.
Compiled source: [40199106358](https://github.com/SawaMEN/VetroffProxy/actions/runs/40199106358).
Successful final runtime verification: [40224778052](https://github.com/SawaMEN/VetroffProxy/actions/runs/40224778052).
The machine-readable [acceptance record](acceptance.json) binds measurements to
both the embedded helper and the exact source lock.

## Changes and regression coverage

The native transaction now keeps a single reader for privileged duplex
streaming uploads. Previously `nsHttpTransaction::Init` cloned the upload pipe,
while the channel retained its original unread cursor. `nsPipe` consequently
retained every transmitted segment for the lifetime of the request. Ordinary
browser uploads keep their private clone. Existing consumed-body replay
protection, certificate validation and bounded pipes are preserved.

The standalone shell now collects temporary wrappers and callback cycles after
16 MiB of traffic, as well as after 64 retired sessions, at the same five-second
minimum cadence. It also reclaims a smaller remainder when all sessions are
idle. This complements the native ownership fix; collecting JS alone did not
remove the unread native pipe cursor. No global memory-pressure notification or
network cache purge is used. Shrinking GC and response-buffer experiments were
discarded. Diagnostic-only cursor-release and memory samples remain attached;
those research helpers are not shipped.

An explicit native response-abort frame now returns `io.ErrUnexpectedEOF`, so
Bond can retry the same sequence-numbered record on another lane. Oversized
frames remain protocol failures. The native regression first reads a real H2
response prefix, resets that stream and checks both the interruption category
and absence of HTTP-adapter replay. The ordinary POST and UDP-v1 no-replay gates
remain mandatory.

Before response headers, Gecko can instead return
`NS_ERROR_NET_UNCLEAN_SHUTDOWN` (`0x804b0065`). The pinned xpcshell reports this
value but does not expose its symbolic name in `Components.results`; the helper
therefore uses the exact value from the pinned `xpcom/base/ErrorList.py` when the
name is absent. Only that network category was added. TLS, authorization and
protocol denials remain terminal. A JS regression covers the missing-name case
and rejects the security/protocol cases.

The Bond outage gate now closes the actual origin TCP connection, including
streams still binding. Closing only a request body had manufactured a terminal
HTTP 400 binding rejection rather than a network loss. The stronger test still
requires uninterrupted binary delivery through the surviving origin.

## Validation

1. CLI/SDK: locally all 12 selected groups passed three times, including
   lifecycle, capacity, setup-context cancellation, half-close, private IPC,
   HTTP no-replay, duplex UDP, multi-node failures, Bond and all XHTTP modes.
   In CI each of the 10 mandatory native groups passed three times; none was
   skipped. Five supplemental raw-runtime research groups are listed as optional
   skips in the acceptance record, separate from the mandatory bundle gates.
2. Network failure: the final native Bond origin-loss test passed 60 consecutive
   repetitions. Invalid-trust, no-replay and malformed-frame checks remain in
   the matrix. Native CI passed outage and QUIC rebinding.
3. Control comparison: standalone/managed Firefox observations and independent
   Firefox-self variation are retained by CI. The successful sequential paired
   resource samples use the same host and runtime, with separate baseline and
   current helper hashes. A single pair does not establish a performance gain.
4. Resources: the final code passed all seven local 60-second workloads;
   independent CI also passed all seven, both 300-second H2/H3 CONNECT gates,
   and the paired 60-second baseline/current workloads.

Local raw managed samples are retained under [local/managed](local/managed).
Each helper remains alive for the final measurement. The six-second settle
budget allows the five-second GC/CC cadence plus its sweep interval to release
idle owners; it is recorded explicitly in every report. The original limits
remain **192 MiB final RSS growth** and **16 FDs above the idle baseline**.
Sampled peaks are retained and are not an instantaneous-peak limit. Profile
removal and process joining are checked after sampling, so killing the helper
cannot satisfy the resource bound. Failed resource assertions retain raw samples.

These are finite loopback, helper-process tests. They do not establish WAN or
whole-client performance, indefinite stability, statistical speedups or DPI
indistinguishability. H3 POST/UDP/Bond, ARM64, native SNI/SPKI/profile overrides
and unified NSS + Necko release packaging remain later stages.

## Final-code CI managed measurements

Raw samples: [ci/managed](ci/managed). Workload: 60 seconds, followed by the
explicit six-second settle budget, with the helper still alive. RSS starts
after warmup; FD idle values precede traffic. These numbers apply to this CI
host and synthetic workload.

| Mode | Verified rounds | RSS warm/final, MiB | FD idle/final |
| --- | ---: | ---: | ---: |
| bond-lanes | 2128 | 144.8 → 247.0 | 37 → 46 |
| h2-post | 2028 | 144.3 → 200.6 | 43 → 45 |
| udp-multi-node | 2746 | 97.6 → 101.7 | 37 → 46 |
| udp-v2 | 2733 | 97.0 → 103.3 | 34 → 45 |
| xhttp-packet-up | 988 | 165.8 → 136.9 | 36 → 46 |
| xhttp-stream-one | 1648 | 137.6 → 179.4 | 34 → 46 |
| xhttp-stream-up | 1692 | 132.5 → 173.4 | 38 → 47 |

The [wire summary](wire-summary.json) retains the exact source/runtime hashes,
per-observation differences and the independent Firefox-self audit. All three
managed H2 samples had equal captured fields. H3 ordered extension/JA3 fields
varied in all three managed samples and in the Firefox-self control; extension
sets and decoded values matched. This remains a limited CONNECT comparison,
not a claim of DPI equivalence.

## Long CONNECT and paired control

Both protocols passed 300 seconds with eight concurrent streams. These raw
[CONNECT samples](ci/connect) retain CPU, all sampled RSS/FD values, exact byte
counters and helper/source hashes.

| Mode | Verified rounds | Upload + download, GiB | RSS warm/final, MiB | Sampled RSS peak, MiB |
| --- | ---: | ---: | ---: | ---: |
| h3-connect | 9944 | 2.4277 | 123.7 → 163.3 | 291.9 |
| h2-connect | 11192 | 2.7324 | 119.6 → 189.7 | 307.0 |

The [paired raw samples](ci/paired) contain baseline and current measurements
from the same CI host/runtime, 60 seconds per protocol and variant. The paired
report was independently regenerated from these files and matched CI exactly.
The observed current-versus-baseline deltas were:

| Mode | Throughput | CPU seconds/GiB | Sampled RSS peak |
| --- | ---: | ---: | ---: |
| h2-connect | +2.96% | -6.09% | -6492 KiB |
| h3-connect | +3.78% | -7.09% | -2556 KiB |

This is one sequential pair, not a statistically established speedup. Historical
samples from a different host remain labelled as non-comparable. Completion
qualifies the CLI/SDK and bounded lab workloads on Linux amd64; it does not
publish or qualify the unified release archives, which remain stage 6.
