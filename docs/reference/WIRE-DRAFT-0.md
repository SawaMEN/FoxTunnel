# FoxTunnel wire draft 0

[Каталог документации](../DEVELOPMENT.md) · [Совместимость и версии](../DEVELOPMENT.md)

> **Статус:** экспериментальная спецификация формата обмена. Не является обещанием совместимости независимых реализаций или будущих версий.

Status: experimental description of the current implementation, not a final RFC.
Identifier: `foxtunnel-draft-0` in binary/package metadata. The current wire does
**not** carry an invented version header: deployments must pin compatible releases.
A future incompatible wire change needs explicit version negotiation and a new
contract; a build tag alone is not wire negotiation.

This protocol/implementation is independent of any panel. A conforming peer may
be implemented in another language. The initial interoperability scope is
single-exit TCP streams. Discovery/bond/control extensions have separate existing
[cluster](../FEATURES.en.md) / [bond](../FEATURES.en.md) documentation; they are not required
for minimal stream peers. Test agreement between two uses of the reference SDK
is not proof of independent implementation interoperability.

## Security and minimal transport

Use TLS 1.3 with certificate chain and hostname verification, optional additional
SPKI pin. Authenticate only after verification. Credentials are nonempty username
(without colon) and password. HTTP header:
`Proxy-Authorization: Basic BASE64(username + ":" + password)`.
For alice/secret the value is `Basic YWxpY2U6c2VjcmV0`.

The minimal transport is ordinary HTTP/2 CONNECT over verified TLS, ALPN h2.
`:method=CONNECT`, `:authority=destination-host:port`; IPv6 hosts use brackets.
Stream request DATA is the destination upload; HTTP 200 response DATA is download.
Response headers are flushed after destination setup. An upload END_STREAM must
half-close the destination write side while allowing response DATA. Cancellation
closes the destination. Reset/ambiguous failure is terminal; do not replay a TCP
byte stream against another destination. This composition uses standard TLS and
HTTP CONNECT, not a new cipher or a claim of cryptographic novelty.

Rejected authentication/ordinary requests use the configured public cover (or
404), without allocating a destination tunnel. Invalid authenticated target or
padding is 400, unavailable destination 502, saturated tunnel admission 503. Errors
never authorize arbitrary fallback. Default server admission is 256 tunnels;
private/loopback/link-local destinations are denied unless explicitly enabled.

## Other native carriers

| Selected mode | Outer request / transport | Inner stream |
|---|---|---|
| h2-post | H2 POST `/.well-known/foxtunnel-stream-v1`, `X-FoxTunnel-Target: host:port` | upload/download bodies; authenticated server maps to CONNECT |
| h3-post | Same POST fields over QUIC/H3 using Go TLS | same stream semantics |
| wss | verified H1 WebSocket at `/.well-known/foxtunnel-ws-v1`, no compression | plaintext H2 connection inside WS binary stream |
| xhttp-stream-one | duplex H2 POST to shared configured XHTTP prefix | plaintext authenticated H2 connection |
| xhttp-stream-up | POST upload plus GET download on prefix + UUID | same |
| xhttp-packet-up | GET download; numbered fixed-length POST uploads | same, ordered reassembly |

WSS/XHTTP carry authenticated H2 CONNECT/POST session bytes, not VLESS; they do
not invoke an Xray executable. Outer and inner authentication are both required.
XHTTP HTTP Host may differ from dial endpoint/SNI; TLS identity is checked
independently. [XHTTP.en.md](../FEATURES.en.md) specifies route/UUID/sequence parsing,
content types, headers, padding, bounded reservations and expiry. Client packet-up
payloads are at most 32 KiB, four unacknowledged sequence positions; complete a
POST body before starting the next. Server reserves at most eight packets, each
at most 64 KiB, including in-progress reads and delivery. Sequence starts at zero,
delivers exactly in order; duplicate/out-of-window/mixed-mode packets fail. ACK
follows ordered delivery, not mere queuing. Missing/stalled bodies expire after
30 seconds. Failed/ambiguous ACK closes the carrier without automatic HTTP replay.
This is a FoxTunnel XHTTP-shaped subset; reference Xray interoperability/XMUX are
not established. Existing [native transport notes](../FEATURES.en.md) cover
carrier details and limits.

## Optional initial-v1 padding

Client requests `X-FoxTunnel-Padding: initial-v1`; enabled server echoes exactly
that value before any payload. Missing/unknown/mismatched negotiation fails.
Each direction independently frames its first eight nonempty records, then
passes remaining bytes through unchanged. Record encoding:

| Field | Bytes | Meaning |
|---|---|---|
| payload length | 2 | unsigned big-endian, 1..16384 |
| padding length | 1 | 0..255 |
| payload | declared length | application bytes |
| padding | declared length | zero-filled bytes, discarded by reader |

Example payload `abc` with two padding bytes: hex `00 03 02 61 62 63 00 00`.
Truncated header/body or invalid payload length is terminal; never reinterpret
malformed framed data as unpadded traffic. Before eight records, clean EOF at a
record boundary is permitted. The decoder does not expose padding. This framing
is inside encrypted transport and is not a Firefox traffic profile.

## Version and integration boundaries

[Compatibility and first-tag acceptance](../DEVELOPMENT.en.md) define version
pinning, incompatible-change requirements and offline archive verification.

Standalone CLI/release artifacts: [../DEVELOPMENT.en.md](../DEVELOPMENT.en.md).
Public Go embedding: [../DEVELOPMENT.en.md](../DEVELOPMENT.en.md). Binary metadata and release manifest
schema 1 are separate from this wire draft. Connection sharing, codec defaults,
TLS backend, HPACK and scheduling can affect behavior without changing stream
payload format; integrations must test their pinned implementation/transport.
Application UDP, TUN, stable C ABI and a cross-language conformance suite are not
included in this draft. No TSPU bypass or browser equivalence is established.
