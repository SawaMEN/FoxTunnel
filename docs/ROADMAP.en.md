[Русский](ROADMAP.md) | **English**

# Roadmap

- [x] Initialize repository and experimental Go module.
- [x] HTTP/2 CONNECT server behind TLS 1.3 with Basic proxy authentication.
- [x] Local SOCKS5 TCP client with certificate validation.
- [x] Basic tests for tunneled roundtrips, authorization and destination filtering.
- [x] Serve an operator-owned static site for ordinary requests and rejected probes.
- [x] Bound CONNECT setup, release cancelled streams, preserve upload half-close.
- [x] Add TLS resumption, filtered dual-stack fallback and local throughput benchmark.
- [x] Add opt-in bounded initial-record padding with explicit negotiation, parser limits, fuzzing and Go/NSS tests.
- [x] Main-node topology/weight discovery: one-address links, refresh/expiry, exit identity and Go/NSS tests.
- [x] Review Sudoku and the official dnstt v1.20260501.0 archive.
- [x] Review current Amnezia/AWG, TUIC v5 and its pinned Wind dependency.
- [x] SNI/SPKI/tls13 links and per-ingress policies, Go/NSS checks and ticket isolation.
- [x] Generated setup/join bundles, private server configuration and atomic ingress registration.
- [x] Pre-handshake socket admission, confined public site and govulncheck CI.
- [ ] TUN/UDP, system routing/DNS/kill switch and individual user credentials.
- [ ] Persistent bond lanes instead of per-block RPC; delivery-based path estimates.
- [ ] Global ingress telemetry and automatic allocation between clients.
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

## Endpoint scheduling and follow-up review

Trusted multi-origin setup failover, round-robin and least-active scheduling
are implemented for both TLS backends, with bounded network-failure cooldown.
See [configuration and limits](ENDPOINTS.en.md) and the
[NaiveProxy/Sudoku review](NAIVE-SUDOKU-REVIEW.en.md).
HTTP/3, bandwidth-aware scheduling, warm pools and Firefox fingerprint parity
remain experiments rather than delivered features.

## Experimental stream bonding

The separate opt-in `--bond` mode carries blocks of one stream through multiple
entries to one common exit. Ordinary whole-stream scheduling remains available.
See [deployment, acknowledgements, limits and tests](BONDING.en.md).
No speed advantage or TSPU resistance is established.
