[Русский](README.md) | **English**

# FoxTunnel

An experimental encrypted tunneling project. The first milestone provides an **authenticated HTTP/2 CONNECT baseline** with a local SOCKS5 client and a TLS server. The longer-term research goal is to test Mozilla NSS and Neqo against this baseline, then assess whether Firefox-like networking behavior offers any measurable benefit.

> **Status: experimental prototype; not ready for production.** The default client uses **Go crypto/tls**; Linux tagged builds can opt into an **experimental NSS TLS backend**. Neither is a complete Firefox stack. It does not reproduce Firefox TLS or HTTP/2 fingerprints and offers only opt-in experimental initial padding. HTTP/3, UDP, censorship-resistance guarantees and 3x-ui integration are not implemented. Do not market it as superior to NaïveProxy.

## Language

Russian is the primary documentation and CLI language. Use `--lang en` on
`foxtunnel` and `ft-fingerprint` for English help and operator messages, for example
`foxtunnel client --lang en --help`. Help works without credentials. Command and
flag names, protocol values and JSON keys stay unchanged. Underlying OS/library
errors may retain their original language. The standalone C probe accepts
`FOXTUNNEL_LANG=en`.

## Build and test

Requires Go 1.26+.

```sh
go test ./... -race
go build -o foxtunnel ./cmd/foxtunnel
```

## Quick local example

Generate a development certificate (do not use a self-signed certificate in a real deployment):

```sh
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 2 \
  -keyout server.key -out server.crt -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
```

Server, terminal 1:

```sh
export FOXTUNNEL_USER='example-user'
export FOXTUNNEL_PASSWORD='replace-with-a-long-random-password'
./foxtunnel server --listen 127.0.0.1:8443 --cert server.crt --key server.key
```

Client, terminal 2, with the **same** environment variables:

```sh
./foxtunnel client --server https://localhost:8443 --ca-cert server.crt
```

Local TCP applications can use `SOCKS5` at `127.0.0.1:1080` (remote DNS resolution is supported when the application sends a SOCKS5 hostname). For the local example only, the server denies loopback/private targets by default. To reach a TCP service on the local machine, restart it with `--allow-private` **only in an isolated test environment**.

## Security properties and limits

- All proxy CONNECT requests require HTTP Basic proxy authorization **inside TLS**. Empty credentials and usernames containing `:` are rejected. Ordinary requests and rejected probes use the public website handler (plain `404` by default).
- The server requires HTTP/2 CONNECT, TLS 1.3 and a TLS certificate; no plaintext tunnel endpoint is exposed by the CLI.
- The client validates the server hostname and certificate; `--ca-cert` adds a trusted CA/certificate without disabling verification.
- The server resolves destination IPs before dialing, and rejects private, loopback, link-local, shared, and selected special-use addresses unless `--allow-private` is explicitly set.
- SOCKS5 is unauthenticated; its default listening address is loopback. **Never expose the SOCKS5 port publicly.**
- Credentials are supplied via environment variables, not command-line arguments; protect process environment and deployment secrets accordingly.
- No UDP, HTTP/3, traffic shaping, domain fronting, browser fingerprint parity, or active-scanning proof is implemented. Initial-record padding is an opt-in experiment.
- This prototype has not had an external security review. Do not use it as an anonymity solution.

## Public website and connection behavior

Serve your own public static website on the same HTTPS listener:

```sh
./foxtunnel server --listen :443 --cert server.crt --key server.key --web-root /srv/public-site
```

Put an `index.html` and only public assets in that directory. Dotfiles and
unindexed directory listings are rejected; symlinks must also point to public
assets. Requests without valid tunnel authentication go to the website handler,
with proxy credentials removed. Without `--web-root`, the listener returns a
plain 404 instead of a product-branded placeholder. This removes one obvious
identifier; it is **not proof of resistance to active probing**. TLS and HTTP/2
still use Go and retain their network fingerprints.

The client reuses HTTP/2 connections and caches up to 32 TLS sessions in memory
for reconnects. No TLS 0-RTT or certificate-verification bypass is enabled.
`--connect-timeout 15s` limits CONNECT setup only, including an unresponsive
server; established streams can last longer. The server races the alternative
IP family after 250 ms (immediately on first-family failure), using only resolved
addresses that passed its destination policy. Stream cancellation releases the
destination socket, while normal TCP half-close keeps the response readable.

See [performance methodology](docs/PERFORMANCE.en.md) for reproducible local tests
and the measurements still needed on real networks.

## Experimental Mozilla NSS data transport

Linux builds can now use NSS for the complete TLS 1.3 data connection:

```sh
go build -tags nss -o foxtunnel ./cmd/foxtunnel
./foxtunnel client --tls-backend nss --server https://your-server.example
```

Requires NSS/NSPR headers, pkg-config and a C compiler. Credentials are still
supplied by `FOXTUNNEL_USER` / `FOXTUNNEL_PASSWORD`; `--ca-cert` is supported.
The backend verifies certificates and requires h2 ALPN. It does not fall back
silently if unavailable. H2 is still Go x/net/http2, and certificate verification
is Go x509; NSS alone does **not** make this a Firefox-equivalent client.
NSS session resumption is disabled in this first adapter; the Go backend keeps
its existing session cache.

See [NSS build, lifecycle and limits](internal/nsstls/README.en.md) and the
[transport strategy based on NaiveProxy, mieru, Hysteria 2, XHTTP and DNSTT](docs/TRANSPORT-STRATEGY.en.md).

## Experimental bounded initial padding

`--padding` on both server and client enables negotiated padding for the first
eight application-data records per direction, followed by raw streaming. The
mode adds at most 4128 bytes per bidirectional stream (excluding H2/TLS and
capability headers), with no artificial delays. A missing/incorrect server
acknowledgement fails setup before application data is sent; it never silently
retries unpadded. Both Go TLS and NSS clients are supported.

This does not modify TLS/H2 fingerprints or prove resistance to DPI. See the
[wire format, compatibility, limits and tests](docs/PADDING.en.md).

## Bounded server capacity

The server defaults to at most 256 authenticated tunnels, including destination
lookup/dial work. `--max-tunnels 128` changes this limit. Excess authenticated
CONNECT requests fail with HTTP 503 before destination work; they are not queued
or retried automatically. Slots are returned on cancellation, errors and normal
stream teardown. Website requests and rejected probes still use the public
handler. This is a resource bound, not a complete TLS/HTTP or DDoS defense.

See the [AmneziaWG 3.1 / AnyTLS / TUIC / WebTunnel / Outline review](docs/PROTOCOL-REVIEW-2026-10-18.en.md)
for what can transfer to the Mozilla design and what still needs experiments.

## Multiple trusted servers

The client can distribute **new streams** across up to eight configured HTTPS
origins. `--balance failover` is the default; `round-robin` and `least-active`
enable parallel use of independent servers. Repeat `--fallback-server` to add
origins. Network setup failures trigger bounded retries and temporary cooldown;
established streams are never replayed. Certificate, HTTP and padding failures
remain terminal. All origins receive the same credentials after TLS verification.

```sh
./foxtunnel client --server https://edge-a.example \
  --fallback-server https://edge-b.example --balance least-active
```

See [selection, recovery and limits](docs/ENDPOINTS.en.md) and the
[NaiveProxy/Sudoku audit](docs/NAIVE-SUDOKU-REVIEW.en.md). Multiple servers do not
combine bandwidth for one stream or establish resistance to TSPU detection.

## Roadmap

1. Validate HTTP/2 baseline against packet captures, test HTTPS CONNECT behavior and error handling.
2. Stabilize the experimental **NSS TLS adapter** and prove differences using packet-level capture and Firefox versioned reference traces.
3. Integrate **Neqo** for experimental QUIC/HTTP/3, with fallback to HTTP/2. Do not deploy Neqo's experimental server in production.
4. Evaluate HTTP/2 and HTTP/3 fingerprints, transport overhead, downtime, performance and censor behavior with reproducible benchmarks.
5. After API stabilization: adapter for sing-box and lifecycle integration in 3x-ui.

## Firefox TLS fingerprint research (second milestone)

`ft-fingerprint` **does not implement Firefox TLS**. It extracts non-secret
ClientHello metadata to establish measured differences against a real Firefox
reference trace. No SNI hostname, session ID, client random, or key share bytes
are persisted. JA3 is informational only and is not an anonymity or security score.

Build the tool and generate a **Go TLS** baseline locally:

```sh
go build -o ft-fingerprint ./cmd/ft-fingerprint
./ft-fingerprint --sample-go --out go.json
```

Capture a **real Firefox ClientHello** on the same computer (separate terminal):

```sh
./ft-fingerprint --listen 127.0.0.1:9443 --out firefox.json
```

Open `https://127.0.0.1:9443/` in Firefox. The browser will report a connection
failure; **this is expected** because the probe only reads ClientHello and never
performs a TLS handshake. For meaningful browser vs client comparisons, use a
consistent host/SNI, OS and network environment, and record Firefox version,
proxy configuration, HTTP settings and whether ECH is enabled.

Compare the two samples:

```sh
./ft-fingerprint --input go.json --compare firefox.json --strict
```

The command reports differences in cipher suites, extension ordering, supported
versions, key shares, ALPN, and legacy JA3 fingerprint. `--strict` exits nonzero
when any compared field differs. The JSON represents a *single handshake only*.
This does not test HTTP/2 SETTINGS, timing, certificate validation, payload
patterns or Firefox Necko behavior. No claim of fingerprint parity is made.

See [architecture](docs/ARCHITECTURE.en.md) and [project milestones](docs/ROADMAP.en.md).

## Native Mozilla NSS experiment

A **standalone NSS/NSPR ClientHello generator** is available under
[`experiments/nss-clienthello`](experiments/nss-clienthello/). It emits a
real NSS TLS 1.3 ClientHello to a loopback-only capture listener, but does
not complete TLS, validate certificates, proxy traffic or integrate with the
Go transport. See its README for build and comparison instructions.

## Experimental stream bonding

The separate opt-in `--bond` mode carries blocks of one stream through multiple
entries to one common exit. Ordinary whole-stream scheduling remains available.
See [deployment, acknowledgements, limits and tests](docs/BONDING.en.md).
No speed advantage or TSPU resistance is established.

## Connection links

The scheme is `vetroff://`. `foxtunnel share --server https://node-a.example`
exports settings and environment credentials. Import with
`foxtunnel client --link-file connection.txt` or `--link-file -` for stdin.
Links contain secrets. [Format and examples](docs/CONNECTION-LINKS.en.md).
