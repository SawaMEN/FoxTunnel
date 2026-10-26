# Stage 4 qualified: native Linux ARM64

Status: **4/4 steps complete, 4/6 stages overall**.
Qualified implementation: `24d74d081f209ba931b70500d8ba407c54fe83cf`.

Both native amd64 and ARM64 source jobs passed in
[source run 40264186586](https://github.com/SawaMEN/FoxTunnel/actions/runs/40264186586).
Both runtime qualification jobs passed in
[run 40264186589](https://github.com/SawaMEN/FoxTunnel/actions/runs/40264186589).
They verified exact source locks, target architecture and binary hashes before
executing packaged launchers, main CLI and SDK. General CI also passed.

[Acceptance](acceptance.json) binds all gates, source/helper hashes and retained
file digests. [Artifact metadata](qualified-artifacts.json) binds the original
ZIP archives. Both source provenance records are retained. The complete previous
2/4 checkpoint remains under `checkpoint-2of4/` as historical evidence.

Each architecture passed 13 mandatory native groups three times with no
mandatory skips. The five optional research-only groups passed in the earlier
research step and intentionally skip in the later bundle-only step. Positive
and TCP-only negative H3 cases, trust, duplex, replay, half-close, Multi-Node,
Bond outages, XHTTP and main CLI/SDK are covered.

`ci/arm64/` and `ci/amd64/` retain raw reports for all 12 managed modes, 300-second
CONNECT workloads, paired 60-second baseline/current workloads and wire summaries.
Every managed report passed final RSS growth (192 MiB after 6 seconds settling),
descriptor (idle plus 16), profile cleanup and process join checks. All five H3
managed modes on both architectures selected protocol 3 with zero TCP accepts.
Both paired reports were independently reproduced from raw samples. Sampled
peaks are preserved, even where higher than final quiescent measurements.

The entire ARM64 package was independently checked against its archive checksum
and manifest: 8267 files and 122 ARM64 ELF binaries. The separate compiled runtime
archive also passed an architecture audit of all 119 ELF files. These checks
complement execution on a native ARM64 runner; cross-compilation alone was never
used as qualification.

Measurements describe the helper on loopback and do not establish WAN speed,
whole-client memory, statistically significant improvement or DPI equivalence.
Wire comparisons use native CONNECT and Firefox with the same patched runtime;
randomized TLS extension order and JA3 differences remain inconclusive. No
POST/UDP-specific fingerprint equivalence is claimed.

Stages 5 and 6 remain: identity/profile settings and unified NSS + Necko archives.
This stage does not qualify the separate Neqo Rust bridge or Android/macOS Necko.
`main` is unchanged.
