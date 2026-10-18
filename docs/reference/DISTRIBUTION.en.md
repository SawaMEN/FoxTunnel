# Standalone versioned distribution

[Русский](DISTRIBUTION.md) | **English**

FoxTunnel is an independent executable/protocol implementation. A panel such as
3x-ui, a desktop client or another language can download and supervise the same
binary. No panel code, database, Xray executable or private service is required.
The public Go SDK is an additional integration route, not a prerequisite.

GitHub Releases supports two explicit triggers: an existing
`vMAJOR.MINOR.PATCH[-pre]` tag, or a reviewed PR changing
`.github/release-request.json` on main. For a request, CI builds and checks all
assets before creating a tag at the exact tested source commit and publishing a
prerelease. Ordinary main commits and PRs build `v0.0.0-ci` without publishing.
Any failed/missing target blocks publication; existing tags/releases are never
replaced. Until a reviewed release exists, pin a reviewed commit rather than a
CI version.

## Artifact contract

| OS | Architectures | Flavors |
|---|---|---|
| Linux | amd64, arm64 | nss |

Exactly **two Linux NSS archives** are published per tag; darwin/macOS, Windows and armv7 are excluded. Format: `foxtunnel_VERSION_linux_ARCH_FLAVOR.tar.gz` (the leading tag `v` is omitted from filenames).

Every archive includes `foxtunnel`, `build.json`, MIT/Go/dependency licenses, and third-party notices. NSS archives additionally bundle unchanged NSS/NSPR/SQLite libraries pinned to Firefox 158.0 in `lib/`, Mozilla license notices, and `mozilla-runtime.json` with source URLs and hashes. NSS needs compatible glibc/libgcc-s1 (Ubuntu 24.04 CI baseline); no host NSS packages are required. Keep the complete extracted directory. The NSS build defaults to NSS for H2/WSS/XHTTP (`auto`); Go TLS remains available via `--tls-backend go`, and H3 continues to use Go QUIC. This is not a complete Firefox networking implementation.

`manifest.json` and `SHA256SUMS` are not generated or published. CI temporarily uses `*.metadata.json` sidecars to check the complete release set; they are not release assets. The embedded `build.json` remains the machine-readable build contract.

## Integration by a panel or client

1. Choose an exact trusted tag and full source commit; do not select `/releases/latest`.
2. Support `linux/amd64` and `linux/arm64`, download the `nss` `.tar.gz` from the tag.
3. Check the archive offline using `scripts/release.py verify` (below); securely extract it into a dedicated version directory, rejecting unsafe names and links.
4. Run `foxtunnel version --json` and verify schema, tag, commit, target, protocol draft, TLS backends and `dirty: false`.
5. Start `foxtunnel client --link-file PRIVATE_FILE --listen 127.0.0.1:1080` or `foxtunnel server --config PRIVATE_SERVER_JSON`. Keep secrets in private files and environment, not shell commands.
6. Stop the old process when deploying a new version, retaining its directory and configuration for rollback.

CPU mapping: x86_64 → amd64, aarch64 → arm64. Windows, macOS and armv7 receive no release archives. The same binary includes `setup/share/cluster-add`. The `version --json` schema allows unknown extra fields but consumers must reject unsupported schemas or protocol drafts.

## Maintainer build

```sh
# NSS: native Linux with the pinned Mozilla runtime and native toolchain
python3 scripts/release.py build --version v0.1.0-alpha.1 \
  --os linux --arch arm64 --backend nss --baseline ubuntu-24.04
# After collecting the two NSS archives and their CI-only sidecars:
python3 scripts/release.py index --version v0.1.0-alpha.1
```

The `index` command validates the complete local set without creating index files. Builds refuse dirty trees and overwriting existing versioned assets. `--allow-dirty` is only for local previews. SOURCE_DATE_EPOCH controls archive timestamps, and builds embed the exact commit. No bit-for-bit reproducibility claim is made.

[Public SDK](SDK.en.md) · [Protocol draft](WIRE-DRAFT-0.md) · [MIT](../../LICENSE)

## Pinned Mozilla runtime

`scripts/mozilla-runtime.lock.json` pins both Linux archives, the corresponding
complete source archive and Mozilla's license notices. Hash verification happens
before extracting a fixed list of regular files. The executable uses ELF
`DT_RPATH=$ORIGIN/lib`, including transitive dependencies; libraries stay byte for
byte as published by Mozilla. Build checks reject wrong ELF architecture, missing
libraries, unknown dependencies, runtime resolution outside the bundle or an
unexpected NSS version. CI tests TLS and XHTTP with these libraries on both native
architectures and inside a minimal Ubuntu container without NSS/NSPR packages.

This pin is a release input, not an automatic security update. A maintainer must
review Mozilla updates, replace binary/source/license hashes together, rerun both
native jobs and issue a new FoxTunnel version. Existing versioned assets stay
unchanged. Ordinary developer `go build -tags nss` and SDK consumers still use the
libraries selected by their own toolchain/runtime; only this release script
constructs the bundle. Matching NSS versions does not establish Firefox TLS/HTTP
fingerprint parity or resistance to TSPU classification.

## Independent downloaded-asset verification

Use Python 3.11+ and a reviewed checkout:

```sh
python3 scripts/release.py verify --input downloaded \
  --version "$RELEASE_TAG" --commit "$RELEASE_COMMIT" --target linux/arm64/nss
```

Without `--target`, verify both Linux NSS archives; with it, only the selected archive is needed. The verifier reads `build.json` directly from each archive, validates version/commit/draft/platform, limits, required members and Mozilla provenance/library hashes, and rejects unsafe paths and special files without extracting or executing code.

**Trust limitation:** there is no separately published checksum or signature. An archive's own `build.json` cannot establish authenticity against malicious replacement. Obtain the archive and expected source commit through a trusted channel; consider additional external integrity verification for deployment. CI validates all two NSS archives, including Go vet/race, SDK and Python tests and two native NSS jobs.

## Release through a reviewed version change

Set only `schema: 1` and a new `version` in `.github/release-request.json`; prepare
notes in `docs/releases/VERSION.md`. PR validation builds CI assets without
publishing. After merging to main, the workflow compares the request file between
before/source commits; only a change enables publication. Full history is needed
for this check; an unknown before commit cannot authorize publication.

All four Linux archives are rebuilt with the requested version and one source commit,
pass index/offline verify and native NSS tests before publication. The publish
job creates the tag at that exact commit. Unchanged requests do not publish again
on ordinary code pushes. Existing tags/releases cause failure rather than
replacement. A subsequent release needs a new version. Existing-tag triggers
remain supported; all releases from this workflow are prereleases.
