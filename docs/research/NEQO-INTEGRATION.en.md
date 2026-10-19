# Neqo / HTTP3: experimental native client

[Русский](NEQO-INTEGRATION.md) · **English** · [Research](README.en.md) · [Roadmap](../planning/ROADMAP.en.md)

> **Scope:** Opt-in Mozilla Neqo HTTP/3 client: pinned build, TLS trust policy, limits, interoperability and fallback. The UDP-only probe uses a different ABI.

Stage four adds Mozilla Neqo 0.33.0 through a Rust static library and C ABI 1.
The first tested target is **Linux amd64**. The server remains the independent
Go/quic-go FoxTunnel server; Mozilla's experimental server is not a production
replacement. Default `h3-post` remains quic-go. Ordinary Linux amd64/arm64 NSS
release archives do not include this backend.

## Build and pins

Use Go 1.26.9, Rust **1.99.1** (rustfmt/clippy), Python 3.11+, git, gcc/g++,
pkg-config, libclang, binutils, unzip and dpkg-deb. On Ubuntu 24.04:

```sh
sudo apt-get install build-essential pkg-config libclang-dev git binutils unzip python3
rustup toolchain install 1.99.1 --profile minimal --component rustfmt,clippy
python3 scripts/build_neqo.py
source rust/neqo-bridge/target/foxtunnel-build/env.sh
go build -tags nss,neqo -o foxtunnel-neqo ./cmd/foxtunnel
./foxtunnel-neqo version --json
```

`scripts/neqo.lock.json` and Cargo.lock pin Neqo commit
`1ec4c2a3ccd7ada264112d1b70b070381557d844`, nss-rs
`ba8a3f6acffc7e25749054969ccbbb3ca615df7f`, NSS 3.130 headers and hash-pinned NSPR
4.39 headers. The existing Mozilla lock supplies unmodified NSS/NSPR runtime
libraries from Firefox 158.0 with SHA-256 verification. A system NSS cannot
silently substitute for that runtime. The generated `build_stamp.h` hashes the
Rust archive to invalidate stale Go/cgo build caches. The builder exports
provenance and Rust dependency license texts/attribution. Running the tunnel
performs no downloads and starts no helper/browser process.

`version --json` reports `quic_backends`, `neqo_version`, `neqo_revision`. Missing
compiled support, ABI mismatch or a non-pinned NSS runtime fails explicitly.
There is no silent quic-go replacement. Regular release workflows remain separate.

## Selection and handshake-only H2 fallback

```sh
foxtunnel-neqo client --server https://proxy.example --transport h3-post \
  --quic-backend neqo --tls-backend auto
# Explicitly allow H2 fallback:
foxtunnel-neqo client --server https://proxy.example --transport h3-post \
  --quic-backend neqo --h3-fallback h2 --quic-handshake-timeout 2s
```

Use the existing credential environment variables. The server must serve UDP and
TCP on the same origin/port with valid TLS and FoxTunnel authorization. Explicit
`--tls-backend nss` is supported; `go` with Neqo is rejected. Without
`--h3-fallback h2` no H2 transition occurs. Default handshake budget is 2 s,
configurable from 100 ms to 10 s. The existing `--connect-timeout` bounds the
whole setup, never an already opened stream's lifetime.

Fallback is allowed only on network failure/timeout **during handshake**, before
any HTTP stream is created. The request body is untouched at that point. CA/SNI/pin,
ALPN/protocol/configuration errors, cancellation and HTTP statuses cannot trigger
it. After a successful H3 probe, request failure never replays it on H2. A network
failure selects H2 for 30 s per origin and TLS policy, then UDP can be probed again.
H2 uses the same URL, CA, SNI and additional SPKI pin, TLS 1.3 and NSS. No redirects.

The three QUIC flags are local, absent from connection links, setup and server
JSON. An imported link must already choose `h3-post` with auto/nss:

```sh
foxtunnel-neqo client --link-file connection.txt --quic-backend neqo --h3-fallback h2
```

SDK: set `ClientConfig{Transport:"h3-post", QUICBackend:"neqo", H3Fallback:"h2",
QUICHandshakeTimeout:2*time.Second}` with the existing CA/ServerName/SPKIPin fields.
The TCP Firefox TLS profile and H2 receive profile are rejected for Neqo rather
than advertised as QUIC/browser preferences.

## Ownership and bounds

One Go actor pins an OS thread for all Rust calls, creation and destruction.
Rust/Rc state never migrates between threads; Rust retains no Go pointers.
Rust panics are contained at the ABI. Go owns UDP; shutdown sends a QUIC close,
closes the socket and joins receive work before destroying the engine.

Each transport allows eight origins and each connection 32 active requests.
The command queue has 64 slots; the UDP queue eight datagrams; upload holds one
32 KiB chunk per request. Response data are read into caller-owned buffers;
cancellation joins accepted work before those buffers can be reused. Connection
receive credit is 1 MiB, local bidi credit 128 KiB, peer bidi streams zero and
peer uni streams eight. Neqo additionally bounds its output/QPACK state. Bridge
metadata limits: 64 KiB headers/128 request fields and 1 MiB/16 certificate chains.
These limits do not describe all native NSS or whole-process memory.

There is no 0-RTT, resumption-token cache, ECH, address migration, WebTransport or
HTTP datagram configuration for fingerprint imitation. Go x509 verifies the same
CA/hostname/SPKI policy before NSS authentication and HTTP creation. This is not
full Necko/browser lifecycle or Firefox fingerprint parity, nor a NaiveProxy/TSPU
performance result.

## Validation

An independent Go HTTP3 server covers data, four concurrent streams, reuse/cold
handshakes without resumption, CA/SNI/pin before credentials, ALPN rejection and
cancellation. Real SOCKS and public SDK tests cover pinning, 2 MiB/half-close,
setup-context lifetime and actual NSS H2 fallback.

A userspace UDP proxy drops actual QUIC datagrams: 5 ms per direction, dropping
every 17th packet independently in each direction. Another keeps UDP open and
discards every packet, exercising a 150 ms budget with fallback enabled/disabled.
This is loopback testing, not field/DPI data or independent bandwidth measurement.
[Commands and saved observations](../measurements/2026-10-19/neqo/README.md).

The `Mozilla Neqo client experiment` workflow runs the pinned build, Rust fmt/
clippy/tests, Go vet/race, external SDK and repeated interop/trust/fallback checks.
Sustained/native-sanitizer work, arm64/other OS support, browser fingerprint work
and independent external audit remain future validation.

Sources: [pinned Neqo](https://github.com/mozilla/neqo/tree/1ec4c2a3ccd7ada264112d1b70b070381557d844),
[pinned nss-rs](https://github.com/mozilla/nss-rs/tree/ba8a3f6acffc7e25749054969ccbbb3ca615df7f),
[Firefox HTTP3](https://firefox-source-docs.mozilla.org/networking/http/http3.html).

## Compatibility with the standalone Neqo UDP probe

The earlier [Rust/C ABI v2 UDP-only probe](../../experiments/neqo-ffi/README.md) is preserved unchanged: it intentionally rejects all certificate authentication, sends no HTTP requests, and has its own `Neqo Rust FFI experiment` CI workflow. The opt-in H3 implementation described above lives in `rust/neqo-bridge` and uses a **different ABI**, a verified CA/SNI/SPKI gate and a separately pinned runtime. The probe must not be used as the full client. Production release packages still exclude both Rust experiments.
