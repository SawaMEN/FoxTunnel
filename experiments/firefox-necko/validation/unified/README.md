# Unified NSS + Necko distributions

Stage 6: **4/4**, overall **6/6**. Qualified code is merged in main through
[PR #49](https://github.com/SawaMEN/VetroffProxy/pull/49). Only main remains on the
remote; the final evidence checkpoint is saved directly there.

## Native archive qualification

[Run 40365922072](https://github.com/SawaMEN/VetroffProxy/actions/runs/40365922072)
qualified source ddf216ed288175a71471f2059c3539c3c1784e10 on native Linux
AMD64 and ARM64. All nine required jobs succeeded; publication was skipped.

| Platform | Qualified artifact | Manifest files |
|---|---|---:|
| Linux AMD64 | [unified-amd64-release-assets](https://github.com/SawaMEN/VetroffProxy/actions/runs/40365922072/artifacts/12674636217) | 8302 |
| Linux ARM64 | [unified-arm64-release-assets](https://github.com/SawaMEN/VetroffProxy/actions/runs/40365922072/artifacts/12674940979) | 8301 |

Each artifact has one full archive, its checksum and native verification report.
These are retained CI assets for v0.0.0-ci, not a newly published public version.
See [qualified-assets.md](qualified-assets.md) for archive hashes and sizes and
[acceptance.json](acceptance.json) for exact scope.

Both actual combined archives passed 14 qualification checks per architecture:
complete manifest/ELF/source identity, deterministic reproduction, native NSS and
unified installation, rollback/reinstallation, actual executable/helper identity,
NSS SDK transfers, seven-carrier CLI/SDK transfers and identity/profile gates.
The complete native runtime resource and wire gates were required dependencies.
Both archives were downloaded and independently verified offline; reports,
workflow evidence and an evidence hash index are retained here.

## Integration into main

The merge retains SOCKS5 cascade support and fixes Linux ETXTBSY during installer
fsync using a readable POSIX descriptor. A real executing-binary regression
covers the fix; Windows retains the existing writable descriptor.

The WSS cascade test now uses a server supporting HTTP/1.1 ALPN. After the fix,
[Tests](https://github.com/SawaMEN/VetroffProxy/actions/runs/40428558103),
[NSS](https://github.com/SawaMEN/VetroffProxy/actions/runs/40428558031) and
[Neqo](https://github.com/SawaMEN/VetroffProxy/actions/runs/40428564808) succeeded on
98030b1. Its source tree is exactly the tree merged into main at 61e598b:
57aa572dd92e95f8a007d9784dc726e0832bc7e0.
See [integration-ci.json](integration-ci.json) for pinned jobs and step results.
Local checks passed: 217 Python tests (2 expected skips), 26 JS tests and
Markdown links.

The archived binaries remain identified as ddf216e; they are not relabeled as
binaries of the later merge. Subsequent main runtime/release builds remain
separate CI runs and are not asserted as completed by this acceptance.

## Distribution scope

Both archives retain the NSS CLI, Necko helper and pinned runtime, NSS libraries,
patches, all notice-referenced licenses, SDK contracts and integrity metadata.
Keep the extracted bundle intact, including runtime/ and lib/. Linux AMD64 and
ARM64 are the qualified platforms. No WAN/DPI or complete Firefox fingerprint
equivalence is claimed. The reviewed version/tag publication policy is unchanged.
