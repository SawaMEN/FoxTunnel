# FoxTunnel integration contract

FoxTunnel is an independent HTTPS tunnel protocol core. It has no dependency
on sing-box or Xray. A client-side implementation and a server-side implementation
are required to speak the protocol; neither is a whole-device VPN application.
The public API and wire draft remain experimental: pin the tested tag and commit.

## Release contents

The standard release publishes only two integration bundles:
`foxtunnel_<version>_linux_amd64_nss.tar.gz` and
`foxtunnel_<version>_linux_arm64_nss.tar.gz`.
Each contains `foxtunnel`, `lib/` with the pinned NSS runtime, `build.json`,
`integration.json`, this file as `INTEGRATION.md`, and required licenses/notices.
Keep the complete bundle together: NSS libraries are loaded relative to the binary.
Ubuntu 24.04 glibc/libgcc baseline is required. These are process bundles, not
`.so`, `.aar`, `.xcframework`, APK, DMG or graphical VPN applications.

The separate experimental Mozilla Linux amd64 bundle also contains Neqo,
its dependency provenance and license records. Its CI reports/metadata remain
internal workflow artifacts; only the runtime archive is attached to Releases.
GitHub's automatically generated source downloads are independent of these assets.

`build.json` identifies the tag, source commit, protocol draft, architecture and
actual compiled transport capabilities. `integration.json` is the versioned
integration contract (schema 1), not a user configuration or a promise of native ABI.
`foxtunnel version --json` reports `product: protocol-core` and
`integration_schema: 1`, as well as the actual compiled backends.
Verify provenance against the expected tag/commit before starting an executable.
Do not load NSS into an unrelated process that already links a different NSS version.

## Hiddify fork: client integration

For a Go host, import `github.com/SawaMEN/FoxTunnel` at a pinned version/commit.
`NewClient(ClientConfig)` creates the protocol connector;
`DialContext(ctx, "tcp", "example.com:443")` returns a tunneled connection.
Close returned connections and call `Client.Close()` when stopping the profile.
`ServeSOCKS(net.Listener)` is the adapter for a host with an existing packet stack;
`Status()`, `NodeStatuses()` and `NotifyNetworkChange()` support diagnostics and
confirmed route changes. See the repository's `examples/embed/main.go` and
`integration/external` consumer tests. Direct public `DialContext` supports TCP;
UDP is opt-in with `EnableUDP` on both ends. Direct datagram APIs are
`ExchangeUDP(ctx, Datagram)` (v1 one-shot) and `OpenUDP(ctx)` (v2 association
with Send/Receive/Close). The OpenUDP context owns the whole association lifetime;
Receive cancellation only cancels its wait, while cancellation of an in-flight
Send terminates the association to avoid partial-frame replay. Client.Close
cancels pending setup and closes owned associations. UDP and TCP share the
MaxConnections budget. Address is host:port (bracket IPv6); DNS resolves at the
exit. MaxUDPDatagram includes the address header: 1232 bytes. The APIs are
experimental; the repository guide is `docs/UDP-H3.md`.
SOCKS5 UDP ASSOCIATE remains available, optionally with `UDPStreaming`.

For a process host on supported Linux architectures:

```sh
./foxtunnel version --json
./foxtunnel client --link-file /private/profile/connection.txt --listen 127.0.0.1:1080
```

The profile file is a secret (mode 0600 in a private directory). Avoid passing
credentials in command-line arguments. The host owns the child process, waits for
SOCKS readiness, and terminates/reaps it on profile switch. Use a host-reserved
loopback port. SOCKS is unauthenticated by default; set independent
`FOXTUNNEL_SOCKS_USER` and `FOXTUNNEL_SOCKS_PASSWORD` if supported by the host.

Hiddify owns VpnService/NetworkExtension, TUN, its TCP/IP packet adapter, socket
protection/bypass for the outer carrier, routes, DNS, IPv6 policy, kill switch,
reconnect and UI. A SOCKS listener alone does not capture device traffic.
Do not route the outer FoxTunnel connection back into its own TUN.
No Android, Apple, Swift, Dart, JNI or C ABI binding is shipped in these bundles.
Those platforms require a separate host bridge/build and platform lifecycle tests;
copying a Linux executable into Hiddify is not a mobile/macOS integration.
The Go core may be built for supported Go targets, while NSS/Neqo have their own
platform restrictions. No external VPN engine is required by FoxTunnel itself.

## 3x-ui fork: server integration

Run FoxTunnel as a separate supervised protocol core rather than an Xray inbound:

```sh
./foxtunnel server --config /private/foxtunnel/server.json
```

The panel generates private configuration using the schema consumed by
`internal/bootstrap.ReadServer`; `foxtunnel setup` remains an optional configuration
generator for development/manual provisioning. See repository `docs/START.en.md`.
For managed users use `--users-file` and `--users-state` together, exclusively of
single-user credentials, or their server JSON equivalents. `foxtunnel access --help`
describes policy validation and aggregate usage inspection. Linux persists the
access ledger. Preserve the private ledger across restarts/upgrades; never publish
credentials, private keys, connection files or per-user policy in public web roots.

The panel owns certificate provisioning, process user, configuration writes,
start/stop/status, resource limits, log retention, updates and rollback. Unix SIGTERM
performs shutdown; SIGHUP reloads certificates and access policy. A failed
certificate reload retains the last valid pair. Do not assume every server setting
is dynamically reloadable: restart the process for other changes. There is no
network management API or Xray JSON compatibility layer advertised here.
For a Go panel `NewServer(ServerConfig)` exposes an `http.Handler`; the host owns
TLS 1.3, HTTP/2, certificates, listeners and shutdown. The process interface is the
recommended initial integration for preserving isolation and independent upgrades.

## Scope changes

The built-in Linux TUN implementation, userspace TCP/IP stack, native VPN launcher,
sing-box companion and their system-routing workflows have been removed.
Protocol transports, UDP relaying, multi-node support, public Go API, server access
control, protocol tests and development-only measurement tools remain.
Old stage reports describe historical tests and do not certify a host VPN client's
routing, DNS or leak protection. No real VDS is required by the integration contract.
