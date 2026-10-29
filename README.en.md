# VetroffProxy

[Русский](README.md)

TCP and UDP over HTTPS. The client exposes SOCKS5; the server forwards traffic.
Use the `vetroff` CLI or Go library, without sing-box or Xray.

## Quick start

Use matching client and server builds. The original v0.1.0 archives from before
the namespace cleanup are incompatible with main; check the source commit in the release notes.

You need a server, domain and TLS certificate. Download the full Linux bundle from
[Releases](https://github.com/SawaMEN/VetroffProxy/releases) or build with Go 1.26.10+:

```sh
go build -o vetroff ./cmd/vetroff
./vetroff version
```

Continue with [server and client setup](docs/START.md) (Russian).

## Features

- HTTP/2, HTTP/3, WebSocket and XHTTP.
- UDP, multiple nodes, Bonding and SOCKS5 cascades.
- Go TLS/quic-go; NSS and Necko in the corresponding Linux builds.

[Documentation](docs/README.md) · [Options](docs/FEATURES.md) · [Go SDK](docs/INTEGRATION.md)

The host application owns TUN and routing. The protocol and SDK are experimental;
a Firefox fingerprint or censorship resistance is not guaranteed.

[MIT](LICENSE)
