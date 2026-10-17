# FoxTunnel

An experimental encrypted tunneling project. The first milestone provides an **authenticated HTTP/2 CONNECT baseline** with a local SOCKS5 client and a TLS server. The longer-term research goal is to test Mozilla NSS and Neqo against this baseline, then assess whether Firefox-like networking behavior offers any measurable benefit.

> **Status: experimental prototype; not ready for production.** The current client uses **Go's crypto/tls, not Firefox's NSS or Neqo**. It does not reproduce Firefox TLS or HTTP/2 fingerprints and has no custom padding, HTTP/3, UDP, censorship-resistance guarantees or 3x-ui integration. Do not market it as superior to NaïveProxy.

## Build and test

Requires Go 1.23+.

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

- All proxy CONNECT requests require HTTP Basic proxy authorization **inside TLS**. Empty credentials are rejected, and unauthenticated probes see `404`.
- The server requires HTTP/2 CONNECT, TLS 1.3 and a TLS certificate; no plaintext tunnel endpoint is exposed by the CLI.
- The client validates the server hostname and certificate; `--ca-cert` adds a trusted CA/certificate without disabling verification.
- The server resolves destination IPs before dialing, and rejects private, loopback, link-local, shared, and selected special-use addresses unless `--allow-private` is explicitly set.
- SOCKS5 is unauthenticated; its default listening address is loopback. **Never expose the SOCKS5 port publicly.**
- Credentials are supplied via environment variables, not command-line arguments; protect process environment and deployment secrets accordingly.
- No UDP support, HTTP/3, padding, traffic shaping, domain fronting, browser fingerprint parity, or active-scanning proof is implemented.
- This prototype has not had an external security review. Do not use it as an anonymity solution.

## Roadmap

1. Validate HTTP/2 baseline against packet captures, test HTTPS CONNECT behavior and error handling.
2. Build an **independent NSS-based TLS adapter** and prove differences using packet-level capture and Firefox versioned reference traces.
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

See [architecture](docs/ARCHITECTURE.md) and [project milestones](docs/ROADMAP.md).
