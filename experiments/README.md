# Research fixtures

These programs collect measurements and exercise native APIs. They are not
the FoxTunnel client/server runtime and are not shipped in integration bundles.

- `nss-clienthello/`: native NSS ClientHello capture probe.
- `neqo-ffi/`: standalone Neqo FFI experiment, C ABI probe and Go H3 fixture.
- `../cmd/ft-fingerprint/` and `../cmd/ft-webprofile/`: measurement tools.
- `../rust/neqo-bridge/`: the opt-in runtime bridge; unlike the standalone
  experiment, this is used by native Neqo builds and must stay in the runtime tree.

Keep native fixtures independently reproducible. Production code in the public
SDK and `cmd/foxtunnel` must not import research packages or measurement helpers.
`python3 scripts/check_core_boundaries.py` verifies the transitive Go dependency
graph; native CI also runs it with `--tags nss` and `--tags nss,neqo`.

Dated results belong in [measurements](../docs/measurements/); implementation
progress belongs in the [current plan](../docs/IMPLEMENTATION-PLAN.md).
