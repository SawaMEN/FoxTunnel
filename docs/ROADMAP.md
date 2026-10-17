# Roadmap

- [x] Initialize repository and experimental Go module.
- [x] HTTP/2 CONNECT server behind TLS 1.3 with Basic proxy authentication.
- [x] Local SOCKS5 TCP client with certificate validation.
- [x] Basic tests for tunneled roundtrips, authorization and destination filtering.
- [x] Serve an operator-owned static site for ordinary requests and rejected probes.
- [x] Bound CONNECT setup, release cancelled streams, preserve upload half-close.
- [x] Add TLS resumption, filtered dual-stack fallback and local throughput benchmark.
- [x] Add opt-in bounded initial-record padding with explicit negotiation, parser limits, fuzzing and Go/NSS tests.
- [ ] Test in multiple OS configurations and behind an HTTPS frontend.
- [x] Bound authenticated destination setup and relay concurrency before DNS/dial.
- [x] Review AmneziaWG 3.1 and additional transport designs with pinned sources.
- [ ] Add rate limiting, HTTP/TLS connection limits, observability without leaking targets/credentials, graceful shutdown and external audit.
- [ ] Capture up-to-date Firefox reference handshake on desktop and mobile; define fingerprint conformance tests.
- [x] Add standalone NSS/NSPR ClientHello capture experiment (not a transport).
- [x] Add experimental Linux NSS TLS 1.3 data adapter with certificate validation and h2 ALPN.
- [ ] Stabilize NSS packaging, pin supported Mozilla versions and compare Firefox fingerprints.
- [ ] Investigate Neqo client-side QUIC/HTTP3 and RFC 9298 CONNECT-UDP; compare overhead.
- [ ] Decide if the Mozilla implementation has measurable advantages relative to Chromium/NaïveProxy.
- [ ] Integrate with sing-box fork and 3x-ui only after protocols and lifecycle stabilize.

**Do not ship this prototype to end users as a censorship-resistant VPN.**
