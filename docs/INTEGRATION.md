# Integration

VetroffProxy provides a Go API and a supervised process interface. It is a protocol
core; the host owns device networking and application UI. Pin a tested tag/commit.
API schema 1, process schema 1 and wire `foxtunnel-draft-0` are separate versions.

## Distribution

The xfd release distributes one artifact per Linux architecture. Linux AMD64
contains an NSS-enabled `vetroff` CLI together with the verified Necko
`runtime/`, helper and `lib/` in one archive. Linux ARM64 still ships NSS
without the full Necko runtime. Keep the extracted bundle intact and use the
executable inside `foxtunnel-necko/` on AMD64. Runtime baseline: Ubuntu 24.04
glibc/libgcc. Automatic engine selection is available with `Engine: "auto"`
(Go SDK opt-in); empty Engine preserves prior SDK semantics.

Verify archive hashes and provenance before running it. `version --json` reports
the actual compiled backends and `product: protocol-core`, integration/SDK/process
schemas. It checks metadata, not provenance by itself.
The additive `feature_stability` map identifies supported XHTTP/TCP Bond modes;
`experimental` still describes the overall SDK/release policy. See [mode guarantees](FEATURES.md#стабильность-xhttp-и-tcp-bond).

There are no APK, DMG, AAR, XCFramework, Swift/JNI/Dart bindings or public C ABI
packages. Go builds support their Go targets; NSS/Neqo have separate restrictions.
Do not load this NSS runtime into a process using an incompatible NSS version.

## Go client

Import `github.com/SawaMEN/FoxTunnel` at a pinned revision.

```go
client, err := foxtunnel.NewClient(foxtunnel.ClientConfig{
    ServerURL: "https://vpn.example.com",
    Credentials: foxtunnel.Credentials{
        Username: "user",
        Password: secret, // load from private host storage
    },
})
if err != nil { return err }
defer client.Close()

conn, err := client.DialContext(ctx, "tcp", "example.com:443")
if err != nil { return err }
defer conn.Close()
// Exchange application bytes through conn.
```

See repository `examples/embed/main.go` and the public definitions in
`foxtunnel.go`, `foxtunnel_sdk.go` and `foxtunnel_udp.go`.

| API | Ownership |
|---|---|
| `NewClient(config)` | No dial; configure before concurrent use |
| `DialContext(ctx, "tcp", address)` | Context bounds setup; returned connection lives until Close/deadline |
| `ServeSOCKSContext(ctx, listener)` | Owns listener; cancellation closes that service and its accepted connections |
| `ServeSOCKS(listener)` | Runs until listener or client closes |
| `Client.Close()` | Idempotently cancels pending setup and closes owned streams, associations and listeners |
| `NewServer(config)` | Returns an HTTP handler; host owns TLS, listeners and shutdown |

`ConnectTimeout` bounds setup, not the lifetime of an established stream.
Use `errors.Is/As` with `net.ErrClosed`, context errors, `ErrCapacity` and
`ErrProtocolNegotiation`; do not parse localized error text.
Never replay application writes after an ambiguous network failure.

`RuntimeInfo()` reports compiled capabilities. `Snapshot()` and `Status()`
provide local state; snapshot counters are not one atomic transaction.
`WatchStatus(ctx, interval)` accepts 100ms–1h, keeps only the latest unread sample,
and closes on cancellation/client shutdown. Sequence gaps are valid.
`NodeStatuses()` includes node origins; treat it as potentially identifying data.
`NotifyNetworkChange()` retires cached QUIC generations for future sessions
without replaying requests or migrating existing destination state.

## UDP API

Enable UDP on both ends. `ExchangeUDP(ctx, Datagram)` is a v1 request/response
with a budget of at most five seconds, further bounded by caller/setup timeouts.
HTTP 204 maps to `ErrUDPNoResponse`; an empty UDP payload is a valid response.

`OpenUDP(ctx)` opens a v2 association. Its context owns the entire association
lifetime; `ConnectTimeout` bounds setup only. `UDPStreaming` selects the SOCKS
adapter mode and does not gate this explicit API.

- `Send(ctx, Datagram)` serializes complete frames. Cancellation during a write
  closes the association to prevent partial-frame replay. Success means sent,
  not delivered.
- `Receive(ctx)` returns one permitted datagram; cancelling the wait preserves
  the association. Returned payload storage belongs to the caller.
- Close associations after use. TCP, UDP and pending setup share `MaxConnections`.

Addresses use host:port, with bracketed IPv6. Names resolve at the exit; replies
contain numeric addresses. Zoned IPv6 is unsupported.
`MaxUDPDatagram` is 1232 encoded bytes **including the address header**:
maximum payload 1222 bytes for IPv4, 1210 for IPv6, variable for names.
An invalid/oversized Send does not close an otherwise healthy association.

The client queues at most 32 replies and remembers 64 requested destinations.
The server allows 16 destination sockets and 32 queued replies per stream,
a 30-second idle flow timeout and ten-minute association lifetime.
v2 reuses a destination socket; v1 does not promise NAT continuity.
No automatic v2-to-v1 downgrade or application replay occurs.
After a lost association, a new one has new NAT state.

Malformed/truncated v2 frames reset the HTTP stream. Custom ResponseWriter
wrappers must forward ResponseController deadlines for bounded shutdown.
UDP delivery, ordering and application response validation remain the host's job.

## Process client

Use a verified executable with a private connection file:

```sh
./vetroff client --link-file /private/profile/connection.txt \
  --listen 127.0.0.1:1080 --events-json --shutdown-on-stdin-eof
```

The Go supervisor `github.com/SawaMEN/FoxTunnel/processhost` avoids linking native
libraries into the host. See repository `examples/process-host/main.go`.

```go
child, err := processhost.StartClient(ctx, processhost.ClientOptions{
    Executable: "/verified/bundle/vetroff",
    LinkFile: "/private/profile/connection.txt",
})
if err != nil { return err }
defer child.Close()
// Use child.Address; observe child.Done()/Wait().
```

The context owns the child lifetime. Paths must be absolute and the profile a
private regular file (0600 on Unix; owner-only ACL on Windows).
The supervisor removes ambient `FOXTUNNEL_*` variables, checks bounded
`version --json` output, then starts a client on `127.0.0.1:0`.
Version timeout is 5s; startup timeout is 10s after that check.
EOF requests shutdown; after 5s an unresponsive child is killed and reaped.
The supervisor does not verify or sandbox an unknown executable.

## Process events

`client` and `server` accept `--events-json` and `--shutdown-on-stdin-eof`.
Diagnostics use stderr; stdout contains JSON Lines:

```json
{"schema":1,"sequence":1,"type":"ready","role":"client","tcp_listen":"127.0.0.1:49152"}
{"schema":1,"sequence":2,"type":"stopped","role":"client","outcome":"shutdown"}
```

Server events use `role: server` and include `udp_listen` when H3 is enabled.
`ready` confirms local bind/configuration, not remote authentication or Internet
access. `stopped` follows cleanup; `serve_failed` has a nonzero exit status.
Startup failure or a crash may produce no events: always inspect process exit.

Continuously drain stdout, terminate/reap on profile switch, and close stdin to
request portable shutdown. EOF shutdown cannot use `--link-file -`.
These runtime flags can be combined with server `--config` or client `--link-file`.

## Server and host responsibilities

A panel can supervise:

```sh
./vetroff server --config /private/vetroff/server.json
```

The JSON schema is defined by repository `internal/bootstrap.ServerConfig`.
Use `setup` as a configuration generator or generate the same schema yourself.
Managed users require both `users_file` and `users_state`, without single-user
credentials. Preserve the private usage ledger across upgrades.

Unix SIGTERM stops the process. SIGHUP independently reloads certificates and
access policy; invalid certificates retain the previous valid pair. Restart
for other configuration changes. Windows hosts can use stdin EOF for shutdown.
A Go server host must provide TLS 1.3, HTTP/2, certificates, listeners and cleanup.

The panel owns provisioning, private files, resource limits, updates and rollback.
The VPN client owns TUN/TCP-IP adaptation, VpnService/NetworkExtension, outer-socket
bypass, routing, DNS, IPv6, kill switch and reconnect. Avoid routing the outer
VetroffProxy socket back into its own TUN. SOCKS5 alone does not capture device traffic;
its default listener has no authentication. Independent local credentials can be
set through `FOXTUNNEL_SOCKS_USER` and `FOXTUNNEL_SOCKS_PASSWORD`.

Integrations with Hiddify/3x-ui are host-side work; no completed integration is
implied. The API and wire extensions remain experimental.
