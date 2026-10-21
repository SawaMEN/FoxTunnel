# Neqo runtime bridge

[Build and tests](../../docs/DEVELOPMENT.md) · [Integration](../../docs/INTEGRATION.md)

This opt-in Linux amd64 bridge implements the runtime Neqo HTTP/3 client.
It is separate from the standalone experiment in `experiments/neqo-ffi/`.

Run `python3 scripts/build_neqo.py` from the repository root and source the
reported `env.sh` before Go builds/tests with `-tags nss,neqo`.
Cargo.lock, rust-toolchain.toml and scripts/neqo.lock.json pin the inputs.
The standard Linux NSS archives use quic-go for H3; Mozilla/Neqo bundles are separate.

[bridge.h](../../internal/neqo/bridge.h) defines ABI 1 and ownership.
One Go actor owns the engine on its creating OS thread. Rust retains no Go pointers;
buffers are borrowed synchronously. ABI panics become terminal errors.
CA/hostname/SPKI validation must complete before HTTP credentials are sent.

The builder exports dependency licenses/provenance and a generated archive-hash
header for Go's build cache. Building the bridge does not publish a release.
