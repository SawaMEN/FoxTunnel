# Firefox transport strategy

The target is a measured, fast Mozilla-based HTTPS tunnel with optional
alternative carriers. No protocol can promise invisibility to all classifiers,
address blocks or traffic correlation. The following choices are a design plan,
not a list of implemented features.

| Reference | Technique to evaluate | FoxTunnel decision / status |
| --- | --- | --- |
| NaiveProxy | Reuse browser networking, authenticated CONNECT behind a site, bounded initial padding | Highest priority. NSS TLS/H2 experiment, public website and opt-in bounded initial padding implemented; complete browser stack not implemented. |
| mieru ("meiru") | Configurable traffic patterns and bounded randomized padding | Evaluate bounded overhead against captures; do not transplant its non-TLS encryption/nonce format into HTTPS. Not implemented. |
| Hysteria 2 | QUIC streams/datagrams, congestion-aware throughput, ordinary web behavior for rejected authentication | Evaluate Mozilla Neqo HTTP/3 and CONNECT-UDP. Do not assume aggressive rate-based congestion control is fastest or matches Firefox. Not implemented. |
| XHTTP/VLESS ("xhttps vless") | Separate transport from proxy request semantics; streaming and separated upload/download modes | Keep a transport boundary and test HTTP streaming carriers separately. Do not add nested VLESS framing or claim CDN compatibility before testing. Not implemented. |
| AmneziaWG 3.1 | Metadata protection, controlled traffic variability, under-load handling | Reviewed at tag v3.1.20260828. Keep UDP-specific obfuscation separate from Mozilla HTTPS; bounded authenticated tunnel admission implemented. See the dated review. |
| AnyTLS | Padding profiles, session reuse and recovery | Evaluate bounded profiles/liveness without copying custom framing or insecure example defaults. Pending. |
| TUIC v5 | QUIC streams/datagrams and migration | Evaluate via Mozilla Neqo; no 0-RTT replay of application data. Pending. |
| WebTunnel / Outline SDK | Real HTTPS frontends and modular carrier interfaces | Reference designs for frontend tests and stream/packet separation. Not integrated. |
| DNSTT | End-to-end security through recursive DNS and transport/session separation | Optional explicit emergency carrier requiring domain delegation and server identity verification. Not a fast primary carrier, not automatic plaintext DNS fallback. Not implemented. |

See the [AmneziaWG and additional-project review](PROTOCOL-REVIEW-2026-10-18.md)
for verified version identifiers, sources, transfer decisions and limits.

## Layer boundaries

1. Local SOCKS5 / eventual sing-box adapter.
2. Authenticated proxy request and stream lifecycle.
3. Carrier: Mozilla NSS + H2 first, Mozilla Neqo + H3 next; HTTP streaming and
   DNS carriers only as separate, measured modes.
4. Address selection and network policy; no automatic downgrade after a
   certificate or authentication failure.

The NSS backend is a real TLS data path, but its HTTP/2 implementation currently
comes from Go's x/net/http2. Its ALPN list and TLS settings are deliberately
minimal and **are not a Firefox profile**. Certificate validation uses Go x509,
not Firefox's verifier. System NSS versions and their cipher/extension choices
must be recorded in captures. Moving to NSS does not by itself prove any DPI
advantage. Necko/Neqo behavior, HTTP/2 SETTINGS, flow control, header order,
connection reuse and timing still need versioned Firefox reference comparisons.

## Next implementation gates

- Collect desktop/mobile Firefox reference traces, with software versions and
  cold/resumed handshake settings; measure NSS differences.
- Stabilize NSS cancellation, error reporting, concurrent reads/writes, trust
  validation and packaging across supported platforms.
- Compare the implemented initial-v1 padding against an unpadded control using
  Firefox/NaiveProxy captures and real network tests. Its explicit negotiation,
  parser limits and overhead budget do not prove a classifier advantage. Keep
  traffic shaping disabled by default.
- Implement Neqo client H3 against an interoperable stable server, then compare
  loss, RTT, bandwidth/CPU and UDP availability against H2 and NaiveProxy.
- Add carrier selection only after transports exist, with cooldowns and setup
  budgets. Never replay an established stream, credentials to arbitrary origins,
  or application bytes after uncertain delivery.
- Add DNS carrier independently, with server authentication across resolvers,
  queue/packet limits and explicit opt-in. A switch cannot recover existing TCP
  sessions without a separate resumable session protocol.

## Primary references checked

- [NaiveProxy architecture and padding specification](https://github.com/klzgrad/naiveproxy)
- [mieru](https://github.com/enfein/mieru) and [traffic patterns](https://github.com/enfein/mieru/blob/main/docs/traffic-pattern.md)
- [Hysteria 2 protocol](https://v2.hysteria.network/docs/developers/Protocol/)
- [XHTTP design discussion](https://github.com/XTLS/Xray-core/discussions/4113)
- [DNSTT protocol](https://www.bamsoftware.com/software/dnstt/protocol.html) and [security notes](https://www.bamsoftware.com/software/dnstt/security.html)
- [Mozilla Neqo](https://github.com/mozilla/neqo)
- [NSS NSPR I/O layering](https://nss-crypto.org/reference/security/nss/legacy/reference/nspr_functions/index.html)

These references inform independently written adapters and experiments; their
source is not copied into FoxTunnel. Check licenses before any code reuse.
