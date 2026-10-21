# Research fixtures

[Development](../docs/DEVELOPMENT.md)

These tools are separate from the client/server runtime and are excluded from
integration bundles.

| Directory | Purpose |
|---|---|
| [nss-clienthello](nss-clienthello/README.md) | Capture a native NSS ClientHello |
| [neqo-ffi](neqo-ffi/README.md) | Standalone Rust/C UDP and certificate-rejection probe |
| [wire-capture](wire-capture/README.md) | Controlled Firefox/NaiveProxy/FoxTunnel observations |
| `../cmd/ft-fingerprint/`, `../cmd/ft-webprofile/` | TLS/H2 measurement tools |

The runtime Neqo bridge lives separately in `../rust/neqo-bridge/`.
`scripts/check_core_boundaries.py` prevents runtime imports of research packages.
Dated results belong in [measurements](../docs/measurements/).
