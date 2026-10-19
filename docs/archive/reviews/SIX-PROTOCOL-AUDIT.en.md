# Six protocols: source review and decisions for FoxTunnel

> **Archived comparison.** Kept for historical research; versions and claims may be outdated. For current features read the [documentation](../../README.en.md).

[Русский](SIX-PROTOCOL-AUDIT.md) | **English**

Reviewed October 18, 2026. FoxTunnel baseline:
`354968360e3b4a6c34e34bcf3e28c0031f983384`.

## Scope and reproducibility

This is a targeted reading of official specifications and selected implementation
paths: connection establishment/reuse, padding, queues, replay defenses,
congestion control and transport selection. It is not an exhaustive security
audit. The external implementations were not run during this review, and no
comparative Russian ISP tests were performed. Earlier coverage was uneven;
this is the first separate review of Shadowsocks 2022 in this project.

The snapshots below are observed repository heads, not claims about latest
stable releases. Full pinned source links are in the corresponding sections
of the [Russian report](SIX-PROTOCOL-AUDIT.md).

| Project | Commit | Commit date |
| --- | --- | --- |
| AnyTLS | `fd6167acd6d73b9fa3e607659951847fbc9e6c50` | 2026-08-03 |
| Hysteria 2 | `ca8fbd874fd6ca82413948de6dc5924405e103e1` | 2026-10-04, author timezone |
| Shadowsocks Rust, SS2022 implementation | `a1bb24282b607eb77f76b8518727fdbde91b96db` | 2026-10-11 |
| Xray-core, XHTTP | `92ccc939aaf4f8965f369cf0b142e005aeaa11d5` | 2026-10-17 |
| mieru | `f7c2c81773d7da47c25c511f2a37dca4a3034d15` | 2026-10-18 |
| NaiveProxy | `0539676ac91d9607caa00869b709e66643b91ac5` | 2026-10-07 |

## Findings and transfer decisions

**AnyTLS:** useful mechanisms include bounded initial padding profiles, stream
opening acknowledgements, heartbeat and idle TLS session reuse. The inspected
client takes a session out of the idle pool and returns it after the stream
closes; do not describe this as continuously packing all concurrent work into
one TCP connection. TCP loss still blocks delivery on that TCP connection.
AnyTLS does not define a browser TLS fingerprint or implement HTTP. Adopt a
bounded warm pool, explicit opening results and demand-driven liveness checks.

**Hysteria 2:** useful QUIC streams, UDP datagrams, pacing and congestion-control
selection. QUIC removes TCP's delivery blocking between streams, while
connection-level resources remain shared. The snapshot includes BBR profiles,
Reno, Brutal and Gecko over Salamander. Gecko fragments and pads long-header
packets, with bounded reassembly; this changes the outer wire format from
browser HTTP/3. Explore standard Neqo/H3 separately, retain H2 when UDP is
unavailable, and evaluate obfuscated UDP independently. Configured-rate Brutal
is not an automatic speed improvement when the bandwidth estimate is wrong.

**Shadowsocks 2022:** useful replay defenses, message-type separation,
request/response binding and economical UDP session state. In Rust, TCP salt
replay insertion follows successful header authentication; UDP packet numbers
are validated against a window. Adopt this validation discipline and bounded
application retry state. The protocol resembles random data rather than HTTPS
and explicitly lacks forward secrecy. Keep ephemeral TLS 1.3 key exchange;
adding SS2022 AEAD inside TLS does not improve its outer camouflage. TLS record
replay defense and deduplicating retried application operations are distinct.

**VLESS + XHTTP:** these are separate layers; HTTP transport is not a replacement
for cryptographic transport. Useful mechanisms include streaming and packetized
upload modes, separate upload/download paths, XMUX connection lifetime/reuse
controls and bounded reordering. In the inspected dialer, `auto` selects a mode
from configuration, including REALITY/download settings, rather than learning
the best mode from network measurements. CDN/front-end behavior requires
deployment-specific tests. Prefer persistent streams for speed and packetized
HTTP as a compatibility option. Splitting directions does not by itself bond
arbitrary exits into one destination TCP socket.

**mieru:** useful session/underlay separation, controlled reuse/rotation,
TCP/UDP and traffic profiles. The inspected `newUnderlay` randomly selects an
endpoint; it is not a bandwidth-aware scheduler for a bonded stream. Its
low-entropy body encoding carries 4/5/6/7 source bytes in 8 encoded bytes:
approximately 100/60/33/14% expansion before other overhead. Applying that
inside TLS would not lower the entropy of outer TLS ciphertext. Adopt modular
profiles and measured path selection; budget padding and delays explicitly.

**NaiveProxy:** its major strength is reuse of Chromium's networking stack,
including HTTP behavior. It supports H2 and H3 CONNECT, bounded initial padding
and ordinary web frontends. The padding implementation treats short server
writes specially. Its usage documentation warns that additional concurrent
tunnels increase detectability and that timeout rotation can break long SSH
sessions. For Firefox, measure complete NSS plus HTTP/2/Necko or Neqo/H3
behavior against a real browser. NSS with Go HTTP/2 is insufficient. Eight
padded initial records do not conceal the entire later traffic shape. Do not
claim H3 as an advantage missing from NaiveProxy.

These transfer decisions are engineering inferences, not claims of source-code
integration or proven resistance to Russian TSPU.

## FoxTunnel status and priorities

| Area | Implemented at baseline | Remaining work |
| --- | --- | --- |
| TLS/HTTP | Verified TLS 1.3, H2 CONNECT, NSS experiment, static public site | Firefox reference traces and full frontend/probe behavior |
| Padding | Negotiated bounded initial-v1 | Versioned bounded profiles and measured network benefit |
| Multiple nodes | New-stream balancing; experimental bond through common exit, ordering/deduplication | Persistent lanes and per-path delivery budgets |
| Automatic tuning | HTTP operation EWMA, cooldown, 4/8-block pipeline | Goodput, RTT variation, loss, data age and global resource limits |
| H3/UDP | Absent | Standard H3 transport, UDP datagrams and H2 fallback |
| TSPU evidence | No field measurements | Comparable ISP deployments and workloads |

The first speed priority is replacing one HTTP RPC per 32-KiB block in the
main bond path with persistent lanes. An eight-block pipeline remains bounded
by in-flight data and acknowledgement time. Preserve ACKs, bounded reassembly
and retransmission of unacknowledged data over another path.

The first camouflage priority is measuring full TLS/H2 behavior against
Firefox, plus public frontend behavior under active probes. H3 is a separate
work item rather than a substitute for this validation.

Bonding ingress nodes tolerates ingress-path failures, but the common exit
remains a failure point and retains its destination-visible IP. Selecting
another exit for new connections requires destination-aware exit policy.
Keeping an established TCP session after losing its exit requires additional
architecture. Arbitrary application requests must not be assumed idempotent
or automatically replayed by the tunnel.

Compare fixed modes before automatic selection, using identical servers and
versioned configurations. Test latency, loss, bandwidth caps, UDP blocking,
then multiple Russian networks. Measure connection/data success, recovery
time, goodput, p95 latency, wire overhead, CPU and memory. Existing local
[performance measurements](../../research/PERFORMANCE.en.md) do not rank protocols in Russia.
This documentation commit does not implement the proposed transports or
remaining work.
