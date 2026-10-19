# FoxTunnel Neqo ABI 1

[Documentation](../../docs/README.en.md) · [Neqo HTTP/3](../../docs/research/NEQO-INTEGRATION.en.md)

> **Opt-in Neqo HTTP/3 client (ABI 1).** Linux amd64 only, separate pinned Rust/NSS toolchain, CA/SNI/SPKI validation before HTTP credentials. Not in public archives.

Build with `python3 scripts/build_neqo.py` from the repository root. Source the
reported env.sh before Go `-tags nss,neqo` builds/tests. Linux amd64 is the initial
supported target; regular release archives exclude this experiment.

The Rust library is statically linked, owns the pinned Mozilla protocol state
and retains no Go pointers. One Go actor pins the creating OS thread for every
ABI call. Caller-provided byte slices are borrowed synchronously. ABI entry
points catch Rust panics and return a terminal negative result; callers discard
the engine after an error. Certificate authentication is paused for Go's ordinary
CA/hostname/pin verification. There is no accepted HTTP request before that gate.

The C declarations and ownership contract are in
[bridge.h](../../internal/neqo/bridge.h). [Full design, trust, queue limits and
fallback rules](../../docs/research/NEQO-INTEGRATION.en.md).

`Cargo.lock` pins all dependencies. `rust-toolchain.toml` and
`scripts/neqo.lock.json` pin compiler and Mozilla revisions. The build exports
Rust dependency license texts and attribution plus provenance; the generated
C header also makes the external Rust archive visible to Go's build cache.
