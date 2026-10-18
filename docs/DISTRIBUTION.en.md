# Standalone versioned distribution

[Русский](DISTRIBUTION.md) | **English**

FoxTunnel is an independent executable/protocol implementation. A panel such as
3x-ui, a desktop client or another language can download and supervise the same
binary. No panel code, database, Xray executable or private service is required.
The public Go SDK is an additional integration route, not a prerequisite.

This change prepares the release pipeline; it does not itself create a release
tag. After this workflow is merged, a maintainer's `vMAJOR.MINOR.PATCH[-pre]` tag
builds all targets, verifies their index, then publishes an experimental GitHub
prerelease. Main and PR runs build the same artifacts without publishing a release. A
failed/missing target prevents publication. Existing releases/assets are never
overwritten by the pipeline. Until a reviewed tag exists, pin a reviewed commit;
do not treat the CI version `v0.0.0-ci` as a supported public release.

## Artifact contract

| OS | Architectures | Build flavors |
|---|---|---|
| Linux | amd64, arm64 | go, nss |
| Linux | armv7 | go |
| macOS | amd64, arm64 | go |
| Windows | amd64, arm64 | go |

Nine archives per tag. `go` is CGO-disabled; `nss` additionally supports Mozilla
NSS on native Linux with unmodified NSS 3.130/NSPR/SQLite libraries from Firefox
158.0 bundled in `lib/`. The host still needs compatible glibc and libgcc-s1 (Ubuntu 24.04 is
the CI baseline); system NSS/NSPR packages are unnecessary. Keep the entire
version directory together: copying only the executable loses its runtime. Neither
flavor is a full Firefox stack. The default CLI TLS backend remains `go` even in
an NSS-capable binary; select `--tls-backend nss` or an NSS-configured link when
needed. macOS/Windows portable assets are cross-compiled; Linux native jobs run
binary/SDK checks, including NSS transfer in a container without host NSS/NSPR. Cross-compilation is not a runtime certification. macOS
notarization, executable signing and package installers are not implemented.

Unix archive: `foxtunnel_VERSION_OS_ARCH_FLAVOR.tar.gz`; Windows uses `.zip`.
The filename version excludes the tag's leading `v`; the manifest includes it.
Example **naming only**, not a claim that this tag already exists:
`foxtunnel_0.1.0-alpha.1_linux_arm64_nss.tar.gz` under tag `v0.1.0-alpha.1`.
Each archive contains the executable, `build.json`, MIT LICENSE, Go/linked-module
license files and third-party notices. NSS archives additionally carry Mozilla
license notices and `mozilla-runtime.json`: exact binary/source URLs, SHA-256
and per-library hashes. Mozilla libraries retain their own licenses. Native builds execute `version --json`
and compare embedded version/source/target/flavor against the package metadata.

Release assets also include `manifest.json` (schema 1) and `SHA256SUMS`. The
manifest lists exact version, source commit, protocol draft, artifact target,
filename, size, SHA-256, runtime requirements and native-smoke status. The index
rejects dirty builds, mixed source commits/versions, unexpected or missing targets,
invalid paths, duplicates and hash/size mismatches. Checksums provide integrity;
there is no detached signature/attestation contract yet.

## Integration by a panel or client

1. Choose an **exact supported tag**, not `/releases/latest`.
2. Download `manifest.json` from the trusted repository's `/releases/download/TAG/`.
3. Select target `OS/ARCH/FLAVOR`, e.g. `linux/arm64/nss`, checking runtime needs.
4. Download that filename from the same tag; verify size and SHA-256 before use.
5. Extract into a dedicated version directory. Reject absolute/traversal archive
   members; do not unpack into the panel's source/configuration directory.
6. Run `foxtunnel version --json`; require schema 1, expected version/commit/target,
   protocol draft and needed TLS backend. Reject `dirty: true` release binaries.
7. Start `foxtunnel client --link-file PRIVATE_FILE --listen 127.0.0.1:1080`, or
   `foxtunnel server --config PRIVATE_SERVER_JSON`. Use argv/env/private files,
   never a shell command containing credentials. Logs use stderr; version JSON
   uses stdout. Host applications own startup, supervision, routing and updates.
8. Stop the old process before switching the version directory; retain the old
   version/configuration for rollback. Active streams do not migrate across versions.

OS mapping: x86_64 → amd64, aarch64 → arm64, armv7l → armv7. An NSS binary is not
selected for an unsupported CPU or OS, and an unavailable backend does not silently
fall back. CLI `setup/share/cluster-add` remain available in the same executable.
Server credentials/configuration are independent of any panel's database schema.

`foxtunnel version --json` is a machine contract, separate from localized help.
Fields include `schema`, `version`, `commit`, `build_date`, `goos`, `goarch`, ARM
`variant`, `go_version`, `build_flavor`, `tls_backends`, `default_tls_backend`,
`protocol_draft`, `experimental`, and `dirty`. Consumers should allow unknown JSON
fields while rejecting unsupported schemas/drafts. Draft/API compatibility is not
yet stable; a release tag identifies an implementation, not automatic compatibility.

## Maintainer build

```sh
python3 scripts/release.py build --version v0.1.0-alpha.1 \
  --os linux --arch amd64 --backend go
# NSS: native Linux, CGO toolchain, NSS/NSPR headers, pkg-config, binutils, unzip.
# Downloads the hash-pinned official Firefox archive; --mozilla-archive permits
# an offline copy (the same pinned SHA-256 is mandatory).
python3 scripts/release.py build --version v0.1.0-alpha.1 \
  --os linux --arch arm64 --backend nss --baseline ubuntu-24.04
# After collecting all nine archives and sidecar metadata in dist/:
python3 scripts/release.py index --version v0.1.0-alpha.1
(cd dist && sha256sum -c SHA256SUMS)
```

The build refuses a dirty source tree or replacement of an existing artifact.
`--allow-dirty` is only for local previews; such artifacts cannot enter a release
index. Build output is excluded from git. SOURCE_DATE_EPOCH controls archive times;
Go builds use trimpath and embed the exact commit. This is not a claim of audited
bit-for-bit reproducibility across different compilers/environments.

[Public SDK](SDK.en.md) · [Protocol draft](WIRE-DRAFT-0.md) · [MIT](../LICENSE)

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
