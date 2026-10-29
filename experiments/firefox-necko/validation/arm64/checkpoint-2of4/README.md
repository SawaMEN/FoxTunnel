# Stage 4 ARM64 checkpoint

Progress: **2/4 qualification steps**, **3/6 stages overall**. This is a
checkpoint, not final ARM64 qualification or release approval.

[Source run](https://github.com/SawaMEN/VetroffProxy/actions/runs/40264186586)
completed the native ARM64 C++ build and all source-workflow networking gates.
[Runtime run](https://github.com/SawaMEN/VetroffProxy/actions/runs/40264186589)
verified architecture and hashes, packaged and executed the native ARM64 launcher
and main CLI/SDK, and passed native integration/wire checks. Its full sustained
resource suite and the amd64 regression job are still pending at this checkpoint.

The [progress record](progress.json) binds the exact candidate, source lock and
helper hashes to confirmed and pending work. [Artifact records](artifacts.json)
contain the immutable ZIP digests. Retained provenance, source-native test
results, source resource samples and wire summaries preserve the completed work.

The source resource reports cover 60 seconds per CONNECT protocol; they do not
replace the pending 12-mode managed or 300-second runtime workloads. Wire audit
has no unexpected differences but remains inconclusive for randomized TLS
extension ordering. It does not establish DPI equivalence. Measurements cover
one native CI runner and the helper process, not WAN or whole-client performance.

The qualified stage-3 branch `xfd` and `main` remain unchanged. Promotion awaits
completion and verification of every pending gate.
