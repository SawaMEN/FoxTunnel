# FoxTunnel

**[Русский](README.md)**

FoxTunnel is an experimental HTTPS tunnel with a local **SOCKS5 proxy**. It forwards application connections through a FoxTunnel server using HTTP/2, HTTP/3, WebSocket or XHTTP.

**Important:** FoxTunnel is not a production-ready, system-wide VPN. UDP and Linux TUN are experimental. Firefox fingerprint equivalence, resistance to network filtering and complete leak protection have **not** been demonstrated.

## Quick start

**1. Get the binary.** Check [GitHub Releases](https://github.com/SawaMEN/FoxTunnel/releases) for your platform, or build using Go 1.26+:

~~~bash
go build -o foxtunnel ./cmd/foxtunnel
./foxtunnel version --json
~~~

The experimental **Go + NSS + Neqo** bundle is available as [v0.1.0-alpha.2](https://github.com/SawaMEN/FoxTunnel/releases/tag/v0.1.0-alpha.2) for **Linux amd64**. It was built before the branches were merged and should not be mistaken for a build of the latest \`main\`.

**2. Set up a server.** Supply your own DNS name and valid TLS certificate:

~~~bash
./foxtunnel setup --server https://vpn.example.com \
  --cert /path/to/fullchain.pem \
  --key /path/to/privkey.pem \
  --out server-config

./foxtunnel server --config server-config/server.json
~~~

**3. Start a client.** Securely transfer \`server-config/connection.txt\` to the client:

~~~bash
./foxtunnel client --link-file connection.txt
~~~

Configure your application to use SOCKS5 at \`127.0.0.1:1080\`.

**Keep the connection file private:** it contains credentials. Never commit it or post it in an issue.

## Features

- TCP forwarding via SOCKS5 and HTTPS
- HTTP/2, HTTP/3, WebSocket and XHTTP transports
- Opt-in Mozilla engine (NSS for TLS/H2 and experimental Neqo for QUIC/H3)
- Experimental UDP ASSOCIATE and Linux TUN (host routes, DNS and leak prevention require separate configuration)
- Multi-server features, bonding, access controls and a Go SDK

To opt into the Mozilla engine on a compatible build:

~~~bash
./foxtunnel client --engine mozilla --link-file connection.txt
~~~

The connection file's selected transport is preserved; Mozilla mode does **not** automatically force HTTP/3.

## Documentation

1. **[Getting started](docs/START.en.md)** — installation, first server and client, troubleshooting.
2. **[Features and configuration](docs/FEATURES.en.md)** — transports, UDP/TUN, Mozilla, security.
3. **[For developers](docs/DEVELOPMENT.en.md)** — architecture, Go SDK, builds, CI and releases.

FoxTunnel remains experimental. Passing local CI is not proof of mobile-carrier compatibility, Firefox impersonation or production readiness.

License: [MIT](LICENSE).
