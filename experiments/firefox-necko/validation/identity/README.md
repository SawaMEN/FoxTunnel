# Native identity and profile acceptance: stage 5

**4/4 complete; overall 5/6 stages.** Qualified for Linux AMD64 and ARM64 in
[runtime run 40321468060](https://github.com/SawaMEN/VetroffProxy/actions/runs/40321468060),
using implementation `23c4eb6` and the exact 28-patch native lock. Both jobs
completed successfully. Qualified work is promoted to `xfd`; `main` is untouched.

| Check | AMD64 | ARM64 |
| --- | --- | --- |
| Mandatory CLI/SDK/native groups | 18 × 3 passed | 18 × 3 passed |
| Managed HTTP/Bond/UDP resource modes | 12 passed | 12 passed |
| Five-minute H2 and H3 CONNECT load | Both passed | Both passed |
| Paired baseline/current H2/H3 controls | 4 × 60 s passed | 4 × 60 s passed |
| Candidate / Firefox self wire trials | 9 / 9 per protocol | 9 / 9 per protocol |
| Unexpected differences outside self controls | 0 | 0 |
| Packaged launcher, process/profile cleanup | Passed | Passed |

The 18 mandatory groups include the main CLI/SDK seven-carrier matrix and 17
managed native groups, each repeated three times. Five older unbundled HTTP
groups passed in the earlier native step; their intentional skips in the
bundle-only matrix do not count as mandatory passes. Job records and filtered
gate logs make that distinction explicit.

Native tests cover SNI without an IP SAN, unchanged network route and HTTP
authority, valid and invalid leaf SPKI pins, hostname/CA denials before any
application request, POST/CONNECT/UDP v1/v2, alternate-origin isolation,
per-node identities, actual TLS/H2 parameters and immutable native API validation.
Negative tests check that their overall context is still live after all four
carriers finish. The TLS signature assertion preserves NSS's real TLS-1.3
PKCS#1 ordering, matching the existing NSS profile gate.

The corrected helper uses shrinking GC after cycle collection on the existing
bounded cadence. Every final resource gate passed the unchanged RSS/FD limits.
All 10 H3 managed resource workloads across both architectures recorded zero
TCP-origin accepts. Independent checks reproduced all raw wire/self-control
and paired resource reports and verified helper/source hashes, binary identities,
transfer counters, duration, resource bounds and process cleanup.

H2 scheduling/HPACK and H3 extension-order/JA3 fields remain **inconclusive**.
They are preserved, never normalized into equality. These lab tests establish
neither ordinary Firefox/DPI equivalence nor WAN/multiday reliability or a
statistically established speedup. Pins and profiles are immutable per helper;
static node pin files cannot be combined with dynamic discovery.

- [Acceptance metadata](acceptance.json)
- [Verified results and runtime hashes](verified-results.json)
- [Evidence file hashes](evidence-sha256.json)
- [AMD64 job and mandatory counts](ci/amd64/workflow-job.json)
- [ARM64 job and mandatory counts](ci/arm64/workflow-job.json)
- [Preserved failed checkpoint](checkpoint-2of4/README.md)

`ci/<arch>/` retains the original wire and integrated-wire observations,
managed resource samples, five-minute CONNECT data, paired controls and job
records. `local-amd64/` is supporting evidence, not a replacement for native ARM64.
The source run compiled both architectures but failed its original ARM64 resource
gate; final consuming gates verified the exact artifact independently and passed.

Stage 6 remains: unified NSS + Necko release distributions. Existing published
unified archives have not been replaced.
