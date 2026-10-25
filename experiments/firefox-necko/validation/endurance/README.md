# Stage 2: CLI/SDK and sustained native resources

Status: **3 of 4 checks confirmed; independent CI resource qualification running**.
Overall plan: **1 of 6 stages complete**. Linux amd64 only.

Candidate helper/SDK code: `b5d86cc2928a0e82066a6b401a9fd83449cca5c9`.
Compiled source: [40199106358](https://github.com/SawaMEN/FoxTunnel/actions/runs/40199106358).
Final runtime verification: [40224778052](https://github.com/SawaMEN/FoxTunnel/actions/runs/40224778052).
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
2. Network failure: the final native Bond origin-loss test passed 60 consecutive
   repetitions. Invalid-trust, no-replay and malformed-frame checks remain in
   the matrix. Native CI also covers outage and QUIC rebinding.
3. Control comparison: standalone/managed Firefox observations and independent
   Firefox-self variation are retained by CI. The remaining sequential paired
   resource samples use the same host and runtime, with separate baseline and
   current helper hashes. A single pair does not establish a performance gain.
4. Resources: the final code passed all seven local 60-second workloads;
   independent CI repeats them, then runs 300-second H2/H3 CONNECT and paired
   60-second baseline/current workloads before acceptance.

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
