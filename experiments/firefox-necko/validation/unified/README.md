# Unified NSS + Necko distributions: stage 6 candidate

Progress **2/4**, overall **5/6**. Work is isolated on `xfd-release`, based on
qualified stage 5. [Build and qualification run 40365922072](https://github.com/SawaMEN/FoxTunnel/actions/runs/40365922072)
uses source `ddf216e`. No promotion or new published release is claimed.

1. Done: audit producer/consumer archive layout, platform and release boundaries.
2. Done: implement both native architectures, original Necko manifest and ELF
   verification before merging, safe root compatibility, empty-file support,
   native installer/rollback, release-note checks and dual native CI index jobs.
3. Pending: qualify the actual combined archives and their installed files.
4. Pending: verify final assets/evidence and promote qualified work to `xfd`.

Expected outputs are one full `foxtunnel_VERSION_linux_amd64.tar.gz` and one
full `foxtunnel_VERSION_linux_arm64.tar.gz`. Both include an NSS-enabled main
CLI, an owned Necko helper and its pinned runtime, NSS libraries, source patches,
licenses and integrity metadata. The ARM64 archive no longer uses the old
NSS-only filename. Original input bundles remain unchanged.

The archive producer emits a canonical root. The consumer also accepts only the
exact historical `foxtunnel-necko/.` directory alias, retaining traversal, link,
duplicate, privileged-mode, size and count rejection. Empty regular marker files
are accepted and hashed. Input Necko manifests, source/helper identities, runtime
provenance and all ELF architectures are checked before output is generated.

CI verifies archive reproducibility, native installation, rollback/reinstallation,
actual executable identity, bundled NSS SDK transfers and installed unified
CLI/SDK identity/profile tests on each architecture. Existing native and NSS
regression gates remain dependencies. Candidate builds cannot publish; the
existing reviewed version/tag publication policy is unchanged. `main` is untouched.

The follow-up also retains every NSS notice-referenced license and SDK contract
file. Existing archive files survive exclusive-creation refusal. The earlier
build `40364764698` is superseded; only `ddf216e` can qualify this candidate.
