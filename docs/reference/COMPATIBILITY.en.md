# Compatibility and the first experimental release

[Русский](COMPATIBILITY.md) | **English**

FoxTunnel remains experimental. Until wire/API stabilization, integrations pin
an exact version, source commit, transport and TLS backend. The shared
`foxtunnel-draft-0` identifier does not promise interoperability among all
experimental commits.

| Contract | Current rule |
|---|---|
| CLI | Commands/flags are not localized; human-readable messages are not an API |
| `version --json`, `build.json` | Schema 1; allow additional fields, reject unknown schemas |
| Wire | `foxtunnel-draft-0` describes an implementation; no on-wire version negotiation |
| Go SDK | Pin an exact tag/commit; API stability before v1 is not promised |
| `vetroff://` | Contains credentials; unknown fields fail; import cannot disable TLS verification |
| Mozilla | Release NSS runtime is pinned independently of wire and updated by a new release |

An incompatible format change requires a new specification, an explicit
negotiation/rejection decision and old-client/new-server tests in both directions.
Do not change the wire while retaining a draft identifier as a compatibility
promise. Without these tests, issue only experimental versions with the tested
pair stated explicitly. Same-version client/server is the initial tested pair;
no independent peer implementation has been certified.

## Checking downloaded assets

Python 3.11+ is required. Use `scripts/release.py`, `release_verify.py` and
`mozilla_runtime.py` from a reviewed checkout. The verifier is offline and neither
extracts archives nor executes their contents.

1. Choose an exact trusted tag and full source commit.
2. Download a supported Linux `.tar.gz` archive from that tag.
3. Verify it with Python 3.11+ from a reviewed checkout:

```sh
python3 scripts/release.py verify --input downloaded \
  --version "$RELEASE_TAG" --commit "$RELEASE_COMMIT" --target linux/arm64/nss
```

Without `--target`, verify both Linux NSS archives; a selected-target verification only needs its archive. `manifest.json` and `SHA256SUMS` are no longer published. CI-only sidecars are not required by consumers. The verifier inspects embedded `build.json`, expected version/commit/schema/draft, archive members, path safety and NSS library hashes without extraction or execution.

**Integrity caveat:** embedded build metadata is not an independently trusted checksum or signature. Obtain the expected commit and release archive from trustworthy sources; a maliciously replaced archive could contain self-consistent forged metadata. Detached signatures/attestations are not currently implemented.

## First-tag acceptance

- A clean reviewed commit, exact `go.mod/go.sum` dependencies, Go 1.26.9 in CI,
  and a Mozilla lock with binary/source archive and license URLs/hashes.
- Go vet/race, the external SDK consumer and Python checks pass for that commit;
  both native NSS jobs test transfers and a container without host NSS/NSPR.
- Both Linux NSS targets are built; local index and independent verify inspect archive contents.
- macOS, Windows and armv7 are excluded from published release builds.
- The tag points to that exact commit; the workflow publishes a prerelease only.
  Existing assets are never replaced. CI assets are not a release before tagging.
- Updates use a separate version directory and retain rollback configuration;
  active TCP streams do not migrate between versions.

This is a reproducible process for obtaining and validating assets, not a
bit-for-bit reproducibility guarantee across compilers/OSes. The Linux NSS
baseline is Ubuntu 24.04; older glibc needs separate testing. Mozilla and Go
updates require ongoing maintenance.

[Distribution](DISTRIBUTION.en.md) · [Wire draft](WIRE-DRAFT-0.md) · [Next steps](../planning/NEXT-STEPS.en.md)

Bond `records-v1` is an explicitly negotiated extension of the existing bond endpoint.
The [data-path specification](../research/DATA-PATH.en.md) defines per-entry legacy
fallback before any operation is sent; original RPC requests remain accepted.
