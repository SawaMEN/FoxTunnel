# Neqo UDP/C ABI probe

[Development](../../docs/DEVELOPMENT.md)

This standalone experiment exercises UDP, timers and certificate rejection.
It always rejects certificates and sends no authenticated HTTP requests.
It uses ABI v2 in `foxtunnel_neqo.h`; the runtime bridge in
`rust/neqo-bridge/` has a separate ABI and implements the opt-in Neqo transport.

On Linux amd64 with the toolchain/NSS dependencies from
`.github/workflows/neqo-ffi-probe.yml`:

```sh
cd experiments/neqo-ffi
cargo test --locked
cargo build --locked
cc -std=c11 -Wall -Wextra -Werror test_bridge.c -L target/debug \
  -lfoxtunnel_neqo -Wl,-rpath,"$PWD/target/debug" -o target/debug/neqo-abi-test
./target/debug/neqo-abi-test
```

`Cargo.lock` pins this experiment's dependencies, independently of the runtime
bridge. Serialize all ABI operations under one owner; Rust must not retain Go
pointers. The caller owns UDP source validation and timers.
A successful rejection probe confirms rejection, not a working tunnel.
