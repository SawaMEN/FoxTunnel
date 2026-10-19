# Neqo / HTTP/3 integration design

[Русский](NEQO-INTEGRATION.md) | **English**

## Current verified architecture

Firefox uses [Neqo](https://github.com/mozilla/neqo) (Rust QUIC/HTTP/3/QPACK with NSS) through Necko and `neqo_glue`. The standalone `experiments/neqo-ffi` bridge now creates Neqo QUIC Initial packets, but FoxTunnel **does not yet use Neqo for actual HTTP/3**: H3 POST uses `quic-go` and Go TLS, while NSS serves TCP H2/WSS/XHTTP. Replacing TLS alone does not reproduce Firefox networking behavior.

Primary references: [Firefox HTTP/3 architecture](https://firefox-source-docs.mozilla.org/networking/http/http3.html), [Mozilla Neqo](https://github.com/mozilla/neqo).

## Phased opt-in client adapter

1. Pin a reviewed Neqo release, Cargo.lock, source tree, licensing and compatible NSS version. Never load unchecked runtime code.
2. Implement a **client-only** Rust FFI bridge for `neqo-http3` / `neqo-transport` (first Linux amd64), with explicit UDP ownership, request/response streams, cancellation and shutdown. Keep the C ABI minimal and versioned; never expose Rust layouts across Go/C boundaries.
3. Enforce system/custom trust roots, SNI, SPKI pin and h3 ALPN; send no authorization headers before peer verification. Cancellation must not leak goroutines, sockets or Rust state.
4. Test `h3-post` against FoxTunnel's existing Go HTTP/3 server: persistent sessions, large uploads, half-close, concurrent streams, packet loss and RTT, blocked UDP and cancellation. Compare independently captured packets against Firefox traces without claiming parity.
5. Expose `--quic-backend neqo` and `-tags neqo` **only after** tested functionality. Published NSS binaries must not silently ship an unfinished Neqo implementation. Explicit Neqo selection must fail if unavailable, never silently substitute `quic-go`.

## Decision today

* Retain working `quic-go` for HTTP/3 without implying Firefox-like QUIC.
* `--tls-backend auto` selects NSS for TCP if compiled in and Go QUIC for H3; explicit NSS with `h3-post` is rejected.
* Keep Go TLS as an internal diagnostic option but not a standalone release artifact.
* Neqo's server is experimental and does not replace the existing FoxTunnel server without review.
* Network fingerprint parity, superior performance and censorship resistance remain unproven.

The first Rust/C ABI probe is at [experiments/neqo-ffi](../../experiments/neqo-ffi/README.md); it generates real Neqo QUIC Initial packets but **has no network receive, certificate authentication or HTTP request handling**. A production-ready Go/Neqo HTTP/3 transport is not implemented.
