# FoxTunnel

**[Русский](README.md)**

FoxTunnel is an independent VPN protocol core for client and server-panel
integration. It carries TCP and experimental UDP over HTTPS transports without
requiring sing-box or Xray. It is not a standalone whole-device VPN application.

Use the public Go API (`NewClient`, `DialContext`, `ServeSOCKS`, `NewServer`) or
supervise the core as a process: `client` provides a local SOCKS5 adapter and
`server` serves the protocol. Hiddify owns device VPN/TUN/routing/DNS; 3x-ui owns
server provisioning, certificates, configuration and process supervision.

## Integration bundles

The standard release ships only Linux amd64 and arm64 NSS core archives containing
`foxtunnel`, pinned `lib/` runtime, `build.json`, `integration.json`,
`INTEGRATION.md` and licenses. Keep the bundle together. The experimental
Mozilla/Neqo variant is a separate Linux amd64 build.
No GUI, APK, DMG, VPN installer, native TUN stack or native-language SDK is included.
Android/Apple/Dart/C bindings require separate host integration work.

```sh
go build -o foxtunnel ./cmd/foxtunnel
./foxtunnel version --json
```

- [Integration contract](docs/INTEGRATION.md): interfaces, lifecycle, platform limits.
- [Manual core setup](docs/START.en.md).
- [Transports and options](docs/FEATURES.en.md).
- [Architecture and development](docs/DEVELOPMENT.en.md).
- [Configuration and diagnostics reference (Russian)](docs/CONFIGURATION.md).
- [Historical plans and measurement index (Russian)](docs/HISTORY.md).

The API and wire draft are experimental; pin a tested tag/commit. Loopback CI
measurements do not prove DPI resistance or host VPN leak protection.
[MIT license](LICENSE).
