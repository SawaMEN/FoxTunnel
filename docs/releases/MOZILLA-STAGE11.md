# Stage 11: experimental Mozilla Linux amd64 prerelease

The original main/tag NSS-only release workflow is unchanged. It does not
contain the native Neqo engine, and must not be described as a complete
Mozilla Engine distribution.

The [Stage 11 workflow](../../.github/workflows/stage11-mozilla-release.yml)
publishes only after a new one-shot update to
`.github/mozilla-release-candidate.json` on branch `update`.
It accepts experimental `v0.1.0-alpha.N` versions and refuses to overwrite
existing tags or releases. A normal source push cannot publish anything.

Only **Linux x86_64 (amd64, glibc)** is supported for the combined Go,
Mozilla NSS 3.130 and Rust Neqo 0.33.0 binary. macOS, Windows, ARM, and
production-grade system-wide VPN networking is not part of the release. The merged code does include opt-in experimental UDP ASSOCIATE and Linux TUN, but no managed routes or kill switch.

## Verification gates

1. Go race tests, external SDK tests, Go vet, release scripts and docs.
2. Pinned source build for the exact version/commit in Linux amd64 CI.
3. Strict offline SHA-256, archive-path, file-type, mode, size, NSS runtime,
   Rust dependency/Neqo provenance, third-party license and build metadata
   verification. The verifier never extracts or executes unknown archives.
4. Extract the **verified** tarball into private ephemeral runner storage,
   execute `foxtunnel version --json`, run real socket NSS/H2 and Neqo/H3
   byte-verified loopback echo tests.
5. Publish the new GitHub **prerelease** with tarball, external metadata,
   `SHA256SUMS`, offline verification and CI-gate result.

The release tarball contains one FoxTunnel executable **and** the pinned
Mozilla dynamic libraries in `lib/`. Keep them in one directory when
extracting; the executable is not fully static.

## Verify the downloaded bundle

Obtain the **actual tagged commit SHA** and version from the trusted
GitHub Release page. Check `SHA256SUMS` before installation, then:

~~~sh
python3 scripts/mozilla_release_verify.py \
  --version v0.1.0-alpha.2 \
  --commit FULL_40_CHARACTER_TAGGED_COMMIT \
  --input downloaded
~~~

The verifier reads the artifact without extracting it, checks internal
metadata against the trusted GitHub commit and validates every member.
Release-hosted checksums are not independent cryptographic signatures:
publisher compromise can replace both binaries and sums.

## Supported scope

This remains an experimental TCP SOCKS5 client/server, **not** a full
VPN: opt-in UDP relay and Linux TUN exist experimentally, but automatic route management and a kill switch are not provided.
Using NSS/Neqo does not reproduce Firefox's complete fingerprint, prove
NaiveProxy equivalence or establish resistance to Russian TSPU/DPI.

CI network tests use isolated loopback. Multi-day external field tests,
mobile-carrier availability, and controlled cross-client QUIC/H3 captures
are not yet complete. Prerelease publication is not a production-quality
certification.
