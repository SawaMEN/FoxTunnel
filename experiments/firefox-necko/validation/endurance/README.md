# Stage 2: sustained managed transports

Status: **3 of 4 checks confirmed; resource qualification pending native rebuild**.
Overall plan: **1 of 6 stages complete**. Linux amd64 only.

1. Main CLI/SDK, lifecycle, cancellation, binary transfer and half-close:
   passed mandatory native gates three times in run 40173889862.
2. Network failure, trust, outage and QUIC rebinding: passed in that run.
3. Control comparison: retained observations and resource reports from run
   40133136426. A single sequential paired comparison is not a statistical
   performance claim; new CI also retains both raw paired sample directories.
4. Sustained resources: blocked by the native upload pipe retention below.
   The updated source lock requires a newly compiled runtime and full native
   gates before this check can be accepted.

## Reproduction and diagnosis

[Runtime run 40173889862](https://github.com/SawaMEN/FoxTunnel/actions/runs/40173889862)
used helper commit d141424 and compiled source run 40129737449. The seven
managed modes ran for 60 seconds each, with one live helper per mode. H2 POST,
XHTTP packet-up, UDP v2 and multi-node passed. XHTTP stream-one/stream-up and
persistent Bond failed the unchanged 192 MiB final RSS growth limit. Sampled
first/final RSS in KiB: stream-one 137336/538440, stream-up 137500/429068,
Bond 145996/579472. FDs stayed bounded.

Research collection by traffic volume, shrinking GC and response buffer reuse
were insufficient and are **not included in the fix**. The attached diagnostic
samples show a stable 5 MiB JS GC heap while native allocated memory grows from
15 MiB to 101 MiB with traffic. This isolates native retention rather than a JS
heap scheduling problem.

The pinned `nsHttpTransaction::Init` clones upload input streams. `nsPipe`
retains segments until *all* input cursors consume them, while the upload
channel retains the original unread cursor. Thus a live request accumulates
previously uploaded data even though each reader has a bounded pipe budget.

A diagnostic-only helper released the original pipe cursor after response
headers on the old runtime. The attached `research-released-cursor-bond.json`
records 1084 binary echo rounds in 60 seconds, RSS 149040 -> 141540 KiB and FDs
82 -> 41, with profile removal and process joining. This is causal research,
**not qualification of the new C++ patch**; that helper is not shipped.

The production source patch avoids the extra transaction reader only when both
streaming upload and the privileged early-response flag are set. Ordinary
browser uploads keep their private clone. Existing consumed-body replay
protection, protocol/trust checks and bounded upload pipes remain in place.
The helper JS is unchanged. The combined transaction patch and exact post-patch
source hash are updated in `gecko.lock.json`.

## Acceptance required after compilation

- Native main CLI/SDK and managed streaming matrix: three passes, no mandatory
  skipped groups, using the newly compiled source lock.
- All seven managed resource modes: 60 seconds each, unchanged FD/RSS limits,
  exact binary transfers, owned profile/process cleanup. Raw reports are kept
  even when a resource assertion fails and include `resource_bounds_passed`.
- Original 300-second CONNECT and paired baseline/current resource gates plus
  the Firefox wire comparison, against the same verified runtime.
- Review the retained sample trends before declaring stage 2 complete. These
  loopback helper process measurements do not establish WAN or whole-client
  performance, nor do finite tests prove indefinite stability.
