# Experimental initial-v1 padding

This opt-in experiment addresses recognizable initial application-data lengths
inside TLS tunnels. It is inspired by NaiveProxy's bounded initial-padding
approach. It does not change TLS ClientHello, HTTP/2 SETTINGS, connection
lifetimes or traffic timing, and is not a Firefox fingerprint profile or proof
of censorship resistance. HTTP/2 and TLS can coalesce/split writes: these are
application records, not a guarantee about network packet sizes.

## Enable explicitly at both ends

Use the existing credentials and certificate setup, with `--padding` on both
server and client:

```sh
./foxtunnel server --cert server.crt --key server.key --padding --web-root /srv/public-site
./foxtunnel client --server https://your-server.example --padding
```

For NSS, build with `-tags nss` and add `--tls-backend nss` to the client. Padding
is disabled by default. There is no sleep, padding-only keepalive, or background
cover traffic.

## Negotiation and compatibility

The client sends exactly one `X-FoxTunnel-Padding: initial-v1` header inside its
authenticated HTTPS CONNECT request. The server acknowledges the same value
only if its padding support is enabled. Unknown, duplicate or combined values
are rejected. The server checks negotiation after authentication but before
resolving/dialing the destination. Rejected unauthenticated probes use the public
website handler with the proxy authorization and padding capability removed.

The client sends no application data until the HTTP/2 response succeeds and
matches the requested capability. Missing, unknown, duplicate or unexpected
acknowledgements fail setup without a raw retry. A padding-enabled server can
still accept a normal unpadded client; an unpadded client rejects an unexpected
padding acknowledgement. A new padded client fails against an older server
without corrupting a destination stream. This experiment is **not advertised
as NaiveProxy wire-compatible**, despite similar record framing.

## Per-direction framing

Each direction independently encodes its first eight nonempty records. A large
write is divided into payloads of at most 16 KiB until the eight-record budget
is exhausted. Empty writes emit nothing. After those records, all remaining
bytes in that direction are passed through unchanged.

| Field | Size | Meaning |
| --- | --- | --- |
| Payload length | 2 bytes | Unsigned big-endian, 1–16384 |
| Padding length | 1 byte | Uniform random integer, 0–255 |
| Payload | Payload length | Application bytes |
| Padding | Padding length | Zero bytes inside encrypted TLS; ignored by reader |

Each record is assembled before writing, with a fresh cryptographic random
padding length. A pooled buffer's padding region is cleared so it cannot send
another stream's plaintext. A framing write failure is terminal; partially
emitted records are not retried as new records.

The decoder validates a complete record before exposing its payload. Zero or
oversized payload lengths fail. EOF at a record boundary is a valid half-close,
even before all eight records have been used. Truncated headers, payloads or
padding fail with unexpected EOF. Decoder storage is bounded and released when
all eight records are consumed; there is no padding allocation in the raw phase.

The maximum extra framing/padding is **2064 bytes per direction**, or **4128
bytes per bidirectional stream**, excluding capability headers and normal H2/TLS
framing. Short exchanges can have a high percentage overhead; this is why the
mode stays explicit and needs comparison against an unpadded control.

## Validation

Tests cover large/small writes, byte-at-a-time reads, bounded overhead, malformed
lengths, truncation at every point of a record, failed/short writes, capability
mismatches, plain-client compatibility, half-close, interactive flushing, raw
transition, Go TLS and NSS data paths. The decoder has a fuzz target:

```sh
go test ./internal/tunnel -run '^$' -fuzz FuzzPaddingDecoder -fuzztime=10s -parallel=2
go test -race ./... -count=1 -timeout=60s
go test -race -tags nss ./... -count=1 -timeout=60s
go test -tags nss ./internal/tunnel -run '^$' \
  -bench 'Benchmark(NSS)?(Padded)?TunnelRoundTrip' -benchmem -benchtime=500ms -count=3
```

These benchmarks reuse an established stream, so they mostly measure the raw
phase after the short initial prefix. They do not measure classifier accuracy
or demonstrate an advantage over NaiveProxy. Real Firefox reference traces,
first-exchange overhead, cold setup, loss/RTT and operator-network tests remain
necessary. HTTP header padding and RST_STREAM padding are not implemented.

Reference: [NaiveProxy padding design](https://github.com/klzgrad/naiveproxy#padding-protocol-an-informal-specification).
