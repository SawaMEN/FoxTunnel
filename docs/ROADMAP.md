# Roadmap

- [x] Initialize repository and experimental Go module.
- [x] HTTP/2 CONNECT server behind TLS 1.3 with Basic proxy authentication.
- [x] Local SOCKS5 TCP client with certificate validation.
- [x] Basic tests for tunneled roundtrips, authorization and destination filtering.
- [ ] Test in multiple OS configurations and behind an HTTPS frontend.
- [ ] Add rate limiting, connection limits, observability without leaking targets/credentials, graceful shutdown and external audit.
- [ ] Capture up-to-date Firefox reference handshake on desktop and mobile; define fingerprint conformance tests.
- [x] Add standalone NSS/NSPR ClientHello capture experiment (not a transport).
- [ ] Investigate NSS client adapter using version-pinned Mozilla packages, secure trust and TLS completion.
- [ ] Investigate Neqo client-side QUIC/HTTP3 and RFC 9298 CONNECT-UDP; compare overhead.
- [ ] Decide if the Mozilla implementation has measurable advantages relative to Chromium/NaïveProxy.
- [ ] Integrate with sing-box fork and 3x-ui only after protocols and lifecycle stabilize.

**Do not ship this prototype to end users as a censorship-resistant VPN.**
