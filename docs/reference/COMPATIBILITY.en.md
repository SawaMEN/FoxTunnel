# Compatibility and the first experimental release

[Русский](COMPATIBILITY.md) | **English**

FoxTunnel remains experimental. Until wire/API stabilization, integrations pin
an exact version, source commit, transport and TLS backend. The shared
`foxtunnel-draft-0` identifier does not promise interoperability among all
experimental commits.

| Contract | Current rule |
|---|---|
| CLI | Commands/flags are not localized; human-readable messages are not an API |
| `version --json`, `build.json`, manifest | Schema 1; allow additional fields, reject unknown schemas |
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

1. Choose an exact tag and full source commit from a trusted source.
2. Download manifest, SHA256SUMS and the selected archive from that tag.
3. Verify them (the operator sets the variables beforehand):

```sh
python3 scripts/release.py verify --input downloaded \
  --version "$RELEASE_TAG" --commit "$RELEASE_COMMIT" --target linux/arm64/nss
```

Without `--target`, verify all nine archives. A single-target check still requires
the full target matrix in the manifest. Consumers do not need sidecar metadata.
Checks cover expected version/commit/schema/draft, targets, SHA256SUMS, archive
size/hash, embedded build.json, required files, NSS provenance and library hashes.
Duplicate JSON keys/files, links, special files, unsafe paths, privileged modes
and release read-limit violations fail. Executable machine code is not analyzed:
after verification and safe extraction on the target OS, separately compare
`version --json` against the metadata.

Checksums establish integrity and consistency, not authorship. A replaced
manifest and archive can agree. Do not obtain the expected source commit solely
from the downloaded manifest; a trusted source is required. Detached signatures
and supply attestations are not implemented.

## First-tag acceptance

- A clean reviewed commit, exact `go.mod/go.sum` dependencies, Go 1.26.9 in CI,
  and a Mozilla lock with binary/source archive and license URLs/hashes.
- Go vet/race, the external SDK consumer and Python checks pass for that commit;
  both native NSS jobs test transfers and a container without host NSS/NSPR.
- Nine targets are built; index and independent verify inspect archive contents.
- macOS/Windows remain cross-builds, without claims of native tests, NSS support
  or executable signing on those systems.
- The tag points to that exact commit; the workflow publishes a prerelease only.
  Existing assets are never replaced. CI assets are not a release before tagging.
- Updates use a separate version directory and retain rollback configuration;
  active TCP streams do not migrate between versions.

This is a reproducible process for obtaining and validating assets, not a
bit-for-bit reproducibility guarantee across compilers/OSes. The Linux NSS
baseline is Ubuntu 24.04; older glibc needs separate testing. Mozilla and Go
updates require ongoing maintenance.

[Distribution](DISTRIBUTION.en.md) · [Wire draft](WIRE-DRAFT-0.md) · [Next steps](../planning/NEXT-STEPS.en.md)
