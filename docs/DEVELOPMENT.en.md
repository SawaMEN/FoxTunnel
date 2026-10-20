# For developers

[Home](../README.en.md) · [Getting started](START.en.md) · [Русский](DEVELOPMENT.md)

[Stage 8: evidence registry, external SDK integrations and audit handoff (Russian)](AUDIT-READINESS.md)

This document collects build instructions, architecture, SDK usage, testing and release policy. Application setup belongs in [Getting started](START.en.md); optional switches are documented in [Features](FEATURES.en.md).

The current [implementation plan and progress](IMPLEMENTATION-PLAN.md) has 10 stages.
Stage numbers in older lab reports belong to the historical plan.

## Project layout

| Path | Responsibility |
|---|---|
| `cmd/foxtunnel/` | CLI entry points |
| `foxtunnel.go` | Public Go SDK |
| `internal/tunnel/` | SOCKS5, HTTPS transport, client, server, authentication |
| `internal/nsstls/` | Mozilla NSS integration |
| `internal/neqo/`, `rust/neqo-bridge/` | Native Rust Neqo QUIC/H3 client |
| `scripts/`, `.github/workflows/` | Reproducible builds, checks, CI and releases |
| `docs/` | Three primary guides, protocol contract and dated evidence |

FoxTunnel is mainly Go; NSS is a native TLS library and Neqo is a Rust library exposed through FFI. Standard Go TLS and quic-go builds remain available.

## Build and test

Requires Go **1.26+**:

~~~bash
go build -o foxtunnel ./cmd/foxtunnel
go test ./...
go test -race ./...
go vet ./...
python3 scripts/check_docs_links.py
python3 scripts/check_core_boundaries.py
go mod tidy -diff
(cd integration/external && go mod tidy -diff)
~~~

To build the pinned **experimental Mozilla Linux amd64** bundle, install the required Go, C/C++, Rust and native toolchains as defined by the repository's pinned build script, then run:

~~~bash
python3 scripts/build_mozilla.py --version v0.0.0-ci
~~~

This builds Go + NSS + Neqo and bundles the native libraries. The output is **not** a single statically linked executable; deploy the entire archive. A plain `go build` does not include the native Mozilla engine.

CI covers Go, NSS, Neqo and real-socket HTTP/2/HTTP/3. Device TUN tests belong to host clients. CI loopback success is not evidence of stable operation on real carrier networks.

## Go SDK

The public import path is `github.com/SawaMEN/FoxTunnel`. Main operations are `NewClient(ClientConfig)`, `DialContext(ctx, "tcp", "host:port")`, `ServeSOCKS`, and `Close()`. A client can expose `Status()` and `NotifyNetworkChange()` for optional Mozilla diagnostics.

The current exact public configuration fields and types are in `foxtunnel.go`. Configure a client before concurrent use; close returned connections yourself. `NewServer(ServerConfig)` returns a handler, leaving TLS listeners, certificates and server lifecycle to the host application.

See `examples/embed/` and the separate `integration/external/` module for API interoperability. Never import `internal/` from another module. Pin your SDK version.

## Protocol and security

FoxTunnel uses TLS 1.3 with HTTP/2 or HTTP/3 and a draft wire format identified as `foxtunnel-draft-0`. For low-level protocol integration see [Wire draft 0](reference/WIRE-DRAFT-0.md). Client/server and SDK compatibility is experimental; pin and test both ends against the same release.

TLS authentication validates CA chain, server hostname and optional SPKI pin. HTTP proxy authentication is separate. Protect connection files, credentials, private keys and destination restrictions. No custom replacement for TLS encryption is used.

## Distribution and releases

Check actual [GitHub Releases](https://github.com/SawaMEN/FoxTunnel/releases) for available architectures and assets. Experimental [v0.1.0-alpha.2](https://github.com/SawaMEN/FoxTunnel/releases/tag/v0.1.0-alpha.2) bundles NSS 3.130 and Neqo 0.33.0 for Linux amd64, from a commit predating the latest `main` merge.

The regular release workflow builds supported tagged platforms. A separate Mozilla workflow creates only explicitly requested experimental Linux amd64 prereleases. Ordinary source pushes do not publish releases. Check trusted checksums, archive and runtime metadata with `scripts/release.py` or `scripts/mozilla_release_verify.py` as appropriate. These checks are not independent cryptographic signatures.

Files under `docs/releases/` are historical release notes, not the current user manual.

## Evidence and limitations

Raw dated measurement data remain in `docs/measurements/`. Existing experiments established local NSS/H2 and Neqo/H3 functionality; some initial HTTP/2 settings matched a saved Firefox 158 observation, while TLS fields differed. Comparable complete NaiveProxy/Firefox/FoxTunnel QUIC/H3 traces are still missing.

`scripts/fingerprint_audit.py`, `scripts/field_h2_h3.py` and `scripts/soak_h2_h3.py` implement structured comparison and local lab testing. Do not present loopback throughput as real Internet performance or missing captures as fingerprint equivalence.

FoxTunnel is experimental, not a certified system VPN or leak-proof censorship bypass. If contributing, document tested platforms and behaviors, preserve existing OS support and never commit secrets or private packet captures.

License: MIT.

See [operations and platform gates](OPERATIONS.md) (Russian) for shutdown signals, live TLS renewal, and remaining installation/signing checks.
