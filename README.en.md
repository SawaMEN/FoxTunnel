# FoxTunnel

[Русский](README.md)

FoxTunnel is a Go tunnel protocol core. It carries TCP and UDP over HTTPS
as a standalone process or Go library, without sing-box or Xray.

The client exposes SOCKS5 on `127.0.0.1:1080`; the server forwards traffic to
destinations. The host application owns TUN, routing and device DNS.

## Start

Download a complete bundle from [Releases](https://github.com/SawaMEN/FoxTunnel/releases)
or build the Go version with Go 1.26.10+:

```sh
go build -o foxtunnel ./cmd/foxtunnel
./foxtunnel version --json
```

- [Setup](docs/START.md) — server, client and troubleshooting (Russian).
- [Options](docs/FEATURES.md) — transports, UDP, nodes and Bonding (Russian).
- [Integration](docs/INTEGRATION.md) — Go API and process contract (English).
- [Configuration and diagnostics](docs/CONFIGURATION.md) — check-config and doctor (Russian).
- [Development](docs/DEVELOPMENT.md) — builds, tests and measurements (Russian).
- [Operations](docs/OPERATIONS.md) — access, certificates and releases (Russian).

Branch `xfd` publishes one archive per Linux architecture. AMD64 combines an NSS-enabled
CLI with the full verified Necko runtime; ARM64 keeps NSS without full Necko.
The AMD64 CLI automatically selects Necko for compatible CONNECT sessions and NSS/Go
for other features. Keep the full extracted directory, including `lib/` and `runtime/`.
No GUI, APK, DMG or system VPN adapter is included.

The API and wire protocol remain experimental: pin a tested tag or commit.
NSS/Neqo do not guarantee a Firefox fingerprint or censorship resistance.
[MIT license](LICENSE).

XHTTP and advanced TCP Bond have a [supported stability contract](docs/FEATURES.md#стабильность-xhttp-и-tcp-bond); their opt-in defaults are preserved. Public Go API and Neqo retain their separate status.
