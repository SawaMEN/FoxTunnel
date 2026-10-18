[Русский](PROTOCOL-REVIEW-2026-10-18.md) | **English**

# Protocol review: 18 October 2026

## Verified AmneziaWG snapshot

The latest observed versioned date tag in `amnezia-vpn/amneziawg-go` is
**v3.1.20260828**, pointing to
**b5928efb6ca19f0153958460c3d141f04abc5c2e**. The observed master head matches
that commit. Official Amnezia documentation describes AWG 3.1. The repository's
`version.go` still contains a legacy date string, so it is not used to infer the
protocol generation. The GitHub Releases page is empty; a tag, an application
release number and a protocol generation are different identifiers.

Primary references:

- [Versioned tree](https://github.com/amnezia-vpn/amneziawg-go/tree/v3.1.20260828)
- [Pinned configuration documentation](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/README.md)
- [Official protocol overview](https://docs.amnezia.org/documentation/amnezia-wg/)
- [Pinned receive/admission code](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/receive.go)
- [Pinned timing code](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/timers.go)

## What transfers to a Firefox-based design

AWG 3 documents header protection, configurable content padding and timing
ranges, alongside junk/signature packets and message-size parameters. Its
carrier is WireGuard-style UDP, whereas FoxTunnel currently uses verified TLS
and HTTP/2. The following are engineering decisions inferred from that review,
not claims that AWG code or a complete AWG transport was integrated.

| Observed approach | FoxTunnel decision |
| --- | --- |
| Padding/timing variability | Evaluate locally bounded profiles against captures, overhead and latency. Keep the current fixed-budget experiment as a control. No remote scripts or arbitrary parameter ranges. |
| Protection of exposed metadata | HTTPS already encrypts H2/application metadata. Study the remaining TLS/QUIC-visible features; do not add an unrelated cipher outside NSS. |
| Junk/signature preambles | Do not prepend AWG packets to TLS or mutate Mozilla QUIC. That would change the chosen carrier rather than preserve Firefox behavior. |
| Packet-size discipline | Measure path-MTU behavior for future Neqo datagrams. No automatic IP fragmentation or unbounded padding. |
| Under-load handling | Bound expensive authenticated proxy work before DNS/destination sockets. Implemented here as a tunnel admission limit, not a copy of AWG cookies. |
| UDP batching | Profile separately when a native datagram carrier exists; UDP syscall optimizations cannot be assumed to accelerate the current C/Go TLS path. |

## Additional projects reviewed

The entries below are candidate design lessons, not implemented transports.

| Project / primary source | Useful design lesson | Decision and limitation |
| --- | --- | --- |
| [AnyTLS protocol](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md) | Configurable initial padding, session reuse, stream-open status and stalled-session handling | Evaluate bounded per-server padding profiles and explicit liveness handling. Keep certificate verification; the reference examples warn about their insecure defaults. No AnyTLS framing copied. |
| [TUIC v5 specification](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md) | QUIC streams/datagrams, migration, explicit UDP session behavior | Evaluate using Mozilla Neqo and standard H3/MASQUE. No TLS 0-RTT application data without a replay-safe design. QUIC features do not prove Firefox parity. |
| [Tor WebTunnel deployment](https://community.torproject.org/relay/setup/webtunnel/) | Ordinary website and HTTPS frontend with a routed tunnel endpoint | Test a real independent frontend and probe-response equivalence. The existing static website is only a first step; WebTunnel compatibility and Tor are not integrated. |
| [Outline SDK](https://github.com/OutlineFoundation/outline-sdk) | Separate stream/packet connections and dialers; compose transport adapters | Preserve independent carrier interfaces and test connectivity/throughput outside the UI. Do not nest transports merely to accumulate features. |

The prior [transport strategy](../architecture/TRANSPORT-STRATEGY.en.md) covers NaiveProxy, mieru,
Hysteria 2, XHTTP/VLESS and DNSTT. Those modes have different network assumptions:
UDP may be unavailable, DNS has a constrained packet budget, and HTTP streaming
requires specific frontend behavior. Combining their wire formats does not
combine their strongest properties automatically.

## Concrete change from this review

The server now admits at most **256 authenticated CONNECT handlers** at once
by default, configurable with `--max-tunnels`. Admission includes DNS and TCP
setup as well as active relaying. Excess work returns HTTP 503 immediately,
without destination lookup/dial or an unbounded waiting queue. Slots are released
on errors and stream teardown. Ordinary website requests and rejected probes
still use the same public handler, including while capacity is exhausted.

This bounds destination work and socket growth; it does not bound TLS handshake
CPU, all HTTP/2 memory, public-site work or bandwidth, and is not DDoS protection.
Per-source rate limiting and HTTP/TLS connection admission remain separate work.
No automatic retry or stream replay was added.

## Next priorities, with measurable gates

1. Versioned Firefox TLS and H2 reference traces: extension/settings order,
   flow control, resumption, close behavior and timing. NSS alone is insufficient.
2. NSS profiling: small-message latency, CPU and allocation costs; compare against
   the Go baseline before changing pooling, scheduling or buffers.
3. Neqo H3/CONNECT-UDP experiment with bounded queues, validated datagram sizes,
   loss/RTT/UDP-blocking tests and a stable interoperable server.
4. Locally bounded padding profiles inspired by AWG/AnyTLS, with capability and
   overhead accounting. Prove effects experimentally rather than maximizing
   randomness or inserting delays by default.
5. Real frontend/probing comparisons and tests on affected operator networks.
   Record successes, failures and changes over time, with NaiveProxy as a control.
6. Explicit optional HTTP-streaming and DNS carriers after the core is stable.
   Preserve server authentication and never replay uncertain application data.

A successful release gate needs connection success, recovery time, throughput,
p95 latency, CPU/memory and identifiable-feature measurements. There is no
credible "best protocol" ranking without specifying the network and workload.
No Internet/TSPU result or superiority over these projects is established here.
