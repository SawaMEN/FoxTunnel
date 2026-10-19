# FoxTunnel — documentation map

[Русский](README.md) · **English** · [Project README](../README.en.md)

Use this index as the **single entry point**. Guides explain operations; architecture explains implementation; reference defines contracts; research and raw measurements document experiments. Historical reviews live in the archive.

> **Current status:** FoxTunnel remains an experimental TCP tunnel. NSS is the default for supported Linux TCP transports in tagged builds; H3 defaults to quic-go. Mozilla Neqo is a separately built Linux amd64 experiment. An experimental opt-in UDP request/reply relay is available; not a full VPN or Firefox clone.

## Start here

- [Setup and first run](guides/SETUP.en.md)
- [Experimental Linux TUN: sing-box, DNS and nftables](guides/LINUX-TUN.en.md)
- [Connection links](guides/CONNECTION-LINKS.en.md)
- [Ingress and endpoints](guides/ENDPOINTS.en.md)

## Architecture

- [System architecture](architecture/ARCHITECTURE.en.md)
- [Native transports and TLS backends](architecture/NATIVE-TRANSPORTS.en.md)
- [XHTTP](architecture/XHTTP.en.md)
- [UDP ASSOCIATE: scope, setup and limits](architecture/UDP.en.md)
- [Cluster and discovery](architecture/CLUSTER.en.md)
- [Bonded data paths](architecture/BONDING.en.md)
- [HTTP/2 receive profile](architecture/H2-RECEIVE-PROFILE.en.md)
- [Padding](architecture/PADDING.en.md)
- [Transport selection strategy](architecture/TRANSPORT-STRATEGY.en.md)

## Reference and operations

- [Security model](reference/SECURITY.en.md)
- [Accounts, revocation and quotas](reference/ACCESS.en.md)
- [Go SDK](reference/SDK.en.md)
- [Wire draft 0 (single-language specification)](reference/WIRE-DRAFT-0.md)
- [Distribution and releases](reference/DISTRIBUTION.en.md)
- [Versions and compatibility](reference/COMPATIBILITY.en.md)

## Research and roadmap

- [Current research](research/README.en.md)
- [FoxTunnel versus VLESS: measurement harness](research/TRANSPORT-COMPARISON.en.md)
- [Measurements and raw evidence](measurements/README.en.md)
- [Single roadmap](planning/ROADMAP.en.md)
- [Historical reviews](archive/README.en.md)

## Where code and experiments live

- `cmd/` — CLI entry points; `foxtunnel.go` — public SDK; `internal/` — implementation, not an API.
- `rust/neqo-bridge/` — opt-in H3 implementation; `experiments/neqo-ffi/` — separate fail-closed UDP probe.
- `scripts/` — pinned builds and verifiers; `.github/workflows/` — CI; `docs/releases/` — release notes.

**Documentation rules:** active instructions must match `main`. Keep test evidence unchanged and date-stamped. Historical designs belong in the archive, not in the quick start. Do not move Go packages or Rust lockfiles for cosmetic reasons.
