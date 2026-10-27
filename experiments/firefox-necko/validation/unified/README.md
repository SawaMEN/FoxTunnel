# Unified NSS + Necko distributions

Stage 6: **3/4**, overall **5/6**; integration and promotion pending.

[Run 40365922072](https://github.com/SawaMEN/FoxTunnel/actions/runs/40365922072)
qualified source ddf216ed288175a71471f2059c3539c3c1784e10 on native Linux
AMD64 and ARM64. All nine required jobs succeeded; publication was correctly
skipped. The two verification reports and workflow evidence are retained here.

Both actual combined archives passed deterministic reproduction, native NSS
installation, unified installation, rollback, immutable reinstallation, helper
verification, NSS SDK transfers, seven-carrier CLI/SDK tests, and native
SNI/SPKI/node pin/TLS/H2 profile gates. The complete runtime resource and wire
gates also passed. This is Linux qualification; no broader platform or
fingerprint equivalence is claimed.

The archives were independently downloaded and verified offline against their
checksums and complete manifests: 8302 files on AMD64 and 8301 on ARM64.
See the per-platform reports for archive identities. These archives belong to
ddf216e, before the subsequent installer fsync fix and integration with main.

The merge preserves the SOCKS5 cascade implementation already on main.
A local preflight exposed Linux ETXTBSY when reopening a mapped executable for
writing during fsync. POSIX sync now uses a read-only descriptor; the regression
test holds a real executable running while syncing. Windows retains the
existing writable descriptor. Local verification: 217 Python tests (2 expected
skips), 26 JS tests, and Markdown links passed. Go integration runs in CI.

Both native archives contain the NSS main CLI, Necko helper and pinned runtime,
NSS libraries, source patches, all notice-referenced licenses, SDK integration
contracts and integrity metadata. Candidate builds cannot publish; reviewed
version/tag publication policy is unchanged.
