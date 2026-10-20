# FoxTunnel wire draft 0

[Каталог документации](../DEVELOPMENT.md) · [Совместимость и версии](../DEVELOPMENT.md)

> **Статус:** экспериментальная спецификация формата обмена. Не является обещанием совместимости независимых реализаций или будущих версий.

Status: experimental description of the current implementation, not a final RFC.
Identifier: `foxtunnel-draft-0`. Legacy requests carry no version header.
The optional [version/capability negotiation](WIRE-NEGOTIATION.md) extension
carries this identifier inside authenticated HTTPS. Strict peers must confirm
it before accepting the response. Zero-value SDK configuration preserves legacy
mode; pin compatible releases in that mode. Binary metadata is not negotiation.
An incompatible payload change requires a new wire identifier and explicit
implementation support; the current implementation supports only draft 0.

This protocol/implementation is independent of any panel. A conforming peer may
be implemented in another language. The initial interoperability scope is
single-exit TCP streams. Discovery/bond/control extensions have separate existing
[cluster](../FEATURES.en.md) / [bond](../FEATURES.en.md) documentation; they are not required
for minimal stream peers. Test agreement between two uses of the reference SDK
is not proof of independent implementation interoperability.

## Security and minimal transport

Use TLS 1.3 with certificate chain and hostname verification, optional additional
SPKI pin. Authenticate only after verification. Credentials use a 1..256-byte printable ASCII username (0x21..0x7e, no colon)
and a 1..1024-byte password. Password bytes may include colons. Exactly one
Proxy-Authorization header is accepted, at most 2048 bytes; its scheme is
case-insensitive Basic followed by one ASCII space. Base64 must be standard,
padded where needed, strict and contain no whitespace. Empty credentials,
duplicate fields and non-ASCII usernames are rejected. HTTP header:
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

## Application UDP relay

UDP is opt-in on both ends and independent of the outer H3/QUIC transport.
Only authenticated H2/H3 POST requests are accepted, with
`Content-Type: application/octet-stream`. UDP bodies use this bounded RFC 1928
packet format (integers are unsigned, network byte order):

| Field | Bytes | Rule |
|---|---|---|
| RSV | 2 | zero |
| FRAG | 1 | zero; fragmentation unsupported |
| ATYP | 1 | 1 = IPv4, 3 = domain, 4 = IPv6 |
| DST.ADDR | 4 / 1+N / 16 | domain has one-byte length N, 1..255, then N bytes |
| DST.PORT | 2 | 1..65535 |
| DATA | remaining | may be empty |

The entire encoded packet is at most **1232 bytes**, including its header.
An IPv4 packet is at least 10 bytes, IPv6 at least 22; a one-byte domain with
empty data is 8 bytes. Domain bytes must exclude NUL, CR, LF, TAB, space,
slash, backslash, `@`, `?`, and `#`. Domain names resolve at the authenticated
exit. Replies contain the resolved numeric IP and the original destination
port. A client must not resolve that hostname locally to check a reply.

**One-shot v1:** POST `/.well-known/foxtunnel-udp-v1`. One raw packet in the
request, at most one raw response packet in HTTP 200. A target read timeout is
HTTP 204 without a packet. Each request has a separate connected UDP socket
and a timeout of min(server dial timeout, 3 seconds). This is request/response,
not a persistent NAT association. HTTP 400 rejects malformed packets, 413
rejects oversized request bodies, 502 reports resolution/dial/send/read failure,
429 reports managed access limits, and 503 reports tunnel capacity.

**Stream v2:** POST `/.well-known/foxtunnel-udp-stream-v2`. Both bodies contain
zero or more frames: a 2-byte length L followed by one complete packet.
L must be 1..1232 and the packet itself must pass the rules above. Length zero,
oversize, truncation, reserved/fragment fields or invalid destinations terminate
the association; they never switch to v1 or unframed traffic. Clean EOF at a
frame boundary closes the association. Server sends/flushed HTTP 200 headers
before reading frames, so strict negotiation finishes before client frames.

The reference server bounds each stream to 16 connected destination sockets,
32 queued replies, a 10-minute association lifetime and a 30-second idle flow
timeout. Full destination tables evict the least recently used flow; a full
reply queue drops packets. Resolution/dial/send failure drops the affected
datagram/flow, rather than introducing an in-band error frame. After HTTP 200,
malformed framing closes the body; HTTP status cannot change mid-stream.

Reference SOCKS ingress binds an association to its TCP peer IP and first valid
UDP source port; unsolicited replies and fragmented packets are rejected.
Literal reply IP and port must match the requested destination (IPv4-mapped
addresses normalize to IPv4); domain replies carry a numeric exit-resolved IP
and matching port. Stream reply permissions are bounded per exit.
This is not cryptographic per-datagram anti-replay. TLS/QUIC authenticates the
carrier; repeated application datagrams can still occur.

## Conformance vectors

[Machine-readable vectors](../../internal/tunnel/testdata/wire-draft-0.json)
define 30 positive/negative Basic-auth, UDP packet/frame and padding cases,
with lowercase hexadecimal bytes. Fields marked `valid: false` must fail.
`TestWireDraftVectors` checks the reference parser/encoder against these fixed
bytes; maximum-size datagrams have separate boundary tests.

The separate external Go module also implements a minimal standard-library
HTTP/2 CONNECT peer, including version rejection, strict confirmation, data
exchange and half-close, without using the FoxTunnel client or internal codecs.
This checks the documented HTTP wire composition, not full cross-language or
cross-version release certification. WSS/XHTTP/bond/cluster still require their
own extension contracts and tests.

## Version and integration boundaries

[Compatibility and first-tag acceptance](../DEVELOPMENT.en.md) define version
pinning, incompatible-change requirements and offline archive verification.

Standalone CLI/release artifacts: [../DEVELOPMENT.en.md](../DEVELOPMENT.en.md).
Public Go embedding: [../DEVELOPMENT.en.md](../DEVELOPMENT.en.md). Binary metadata and release manifest
schema 1 are separate from this wire draft. Connection sharing, codec defaults,
TLS backend, HPACK and scheduling can affect behavior without changing stream
payload format; integrations must test their pinned implementation/transport.
Device TUN, stable C ABI and a full cross-language conformance suite are not
included in this draft. No TSPU bypass or browser equivalence is established.
