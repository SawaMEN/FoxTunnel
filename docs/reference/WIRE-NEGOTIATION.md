# Draft-0 version and capability negotiation

[Wire specification](WIRE-DRAFT-0.md) · [Development](../DEVELOPMENT.md)

This optional extension preserves draft-0 payload bytes and route names. It is
an authenticated per-request offer/confirmation, not a new cipher, browser
fingerprint, server discovery service, or a promise of future compatibility.
Only `foxtunnel-draft-0` is implemented today. Release/package versions and wire
versions are separate.

## Deployment policy and sequence

Configure `RequireProtocolNegotiation: true` in the public Go `ClientConfig`
and `ServerConfig` to require negotiation. Zero values intentionally retain
legacy deployment policy, so old integrations continue to work. The CLI and
existing profiles retain their legacy behavior; native host bindings/CLI policy
plumbing are separate integration work. A strict client must never retry in
legacy mode after a refusal, missing confirmation or unknown version.

TLS verification and proxy authentication precede protocol handling. The new
server validates a version/capability offer before reading a TCP/UDP body,
resolving a destination or allocating a destination socket. Managed-access
admission still precedes this validation; invalid versions may consume an
authenticated request attempt, but never destination traffic.

For TCP, upload bytes are withheld until the successful response headers.
UDP stream-v2 headers likewise precede frames. UDP one-shot-v1 carries its
datagram in the HTTP request, so a pre-extension legacy server can process the
datagram before the strict client rejects its missing confirmation. Strict
one-shot response validation is not a pre-send handshake with legacy servers.
Use a known strict server or stream-v2 if confirmation before payload is needed.

Negotiation applies to CONNECT and the TCP/UDP POST routes, including the inner
H2 session of WSS/XHTTP. Outer WSS/XHTTP handshakes, cluster and bond RPCs are
separate extensions; these headers do not certify their wire compatibility.
No network probing or persistent version cache is added.

## Request fields

| Field | Cardinality | Meaning |
|---|---|---|
| X-FoxTunnel-Version | exactly one when negotiating | exact case-sensitive `foxtunnel-draft-0` |
| X-FoxTunnel-Require | zero or one | required capability tokens |

Header names are case-insensitive. Duplicate fields, including mixed-case
duplicates supplied by an embedding host, are invalid. A Require field without
Version is invalid. A capabilities list is 1..256 bytes, at most 8 distinct tokens
of 1..32 bytes each; token bytes are lowercase a-z, digits, hyphen. Commas separate
tokens; optional ASCII spaces/tabs around each token are ignored. Empty tokens,
duplicates, CR/LF/control bytes and uppercase tokens are invalid.

| Capability | Meaning / server support |
|---|---|
| tcp | core TCP forwarding; unavailable on bond-only relays |
| udp-v1 | one-shot relay; requires EnableUDP and a non-relay exit |
| udp-stream-v2 | framed streaming relay; same opt-in requirement |
| padding-initial-v1 | initial-eight-record padding; requires Padding |

Strict reference clients require tcp for TCP requests, adding
padding-initial-v1 when enabled; UDP requests require their exact UDP mode.
The independent padding request/echo remains mandatory when padding is selected.

## Responses and errors

A compatible authenticated offer receives `X-FoxTunnel-Version` with the exact
selected version and `X-FoxTunnel-Capabilities` listing enabled capabilities
using the same list grammar. The list is deterministic: tcp, then udp-v1 and
udp-stream-v2 if enabled, then padding-initial-v1 if enabled. Confirmation
headers can accompany an application error; they do not imply target setup
success. Clients require both successful route status and compatible headers.

Malformed/duplicate fields or unsupported required capabilities produce HTTP
400. A missing version on a strict server, empty version or unsupported version
produces HTTP 426. These errors do not echo arbitrary input, credentials or
supported-version lists and do not permit downgrade. No HTTP/1 Upgrade exchange
is performed. Authentication failure uses the ordinary cover handler and exposes
no protocol confirmation; public/rejected cover requests have FoxTunnel headers
removed.

A strict client rejects a missing, duplicate, malformed or different confirmed
version, or a capabilities list missing any required token. It closes response
and upload resources and returns a terminal error; neither failover nor body
replay is permitted after any HTTP response. In the Go SDK,
`errors.Is(err, foxtunnel.ErrProtocolNegotiation)` identifies invalid successful
response confirmation. HTTP refusals remain terminal setup errors with status.

## Compatibility matrix

| Client | Server | Result |
|---|---|---|
| Legacy | Legacy-compatible new server | Existing draft-0 behavior; no negotiation guarantee |
| Legacy | Strict new server | 426, before target resolution/body processing |
| Strict new | Compatible new, either policy | Confirm exact draft and required capabilities |
| Strict new | Pre-extension server | Reject missing confirmation; never retry in legacy mode |
| Explicit unsupported version | New server, either policy | 426 before destination work |
| Strict new | Missing/disabled required capability | Reject/refuse; no mode downgrade |

No actual draft-1 implementation exists: future-version tests use deliberate
unsupported values and cannot establish real draft-0/draft-1 interoperability.
The old-peer fixtures intentionally omit the new headers. Pin old binaries
separately when certifying a release compatibility matrix.

## Executable revision check

The dedicated `Wire draft compatibility` workflow builds the actual previous
CLI from `97036bf8dafddff7c46497c91488a87222132b05` and runs it against the
current Go SDK. It verifies legacy-client/current-server and
current-client/legacy-server TCP/H2 echo, plus refusal when the current side
requires negotiation. This complements missing-header and future-version
fixtures; it is not certification of every published archive or UDP/extension
combination across all historical tags.
