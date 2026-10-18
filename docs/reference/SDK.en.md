# Public embedding API

[Русский](SDK.md) | **English**

The primary integration route is the [standalone versioned executable](DISTRIBUTION.en.md).
Go projects may additionally import `github.com/SawaMEN/FoxTunnel`. Its public
package does not expose internal types, require the CLI, a subprocess or 3x-ui.
MIT is supplied at the repository root; bundled dependency licenses remain separate.
Until tagged releases exist, pin a reviewed commit. The SDK is experimental.

```go
client, err := foxtunnel.NewClient(foxtunnel.ClientConfig{
    ServerURL: "https://proxy.example",
    Credentials: foxtunnel.Credentials{Username: user, Password: password},
    Transport: "xhttp-packet-up",
})
if err != nil { return err }
defer client.Close()
conn, err := client.DialContext(ctx, "tcp", "destination.example:443")
```

`DialContext` returns net.Conn; context/deadline controls establishment only.
Close the returned connection to cancel its lifetime. It supports independent
read/write deadlines that can be cleared after timeout, and optional
`interface { CloseWrite() error }` to finish upload while reading the response.
Addresses are logical FoxTunnel addresses. Only network `tcp` is supported:
remote exit policy selects IP family, so tcp4/tcp6/UDP are not silently accepted.
Padding applies through the same negotiated codec as SOCKS. The connection
bridge uses bounded pipe/copy buffers, not a complete payload buffer.

Client.Close is idempotent, cancels pending direct dials and closes owned
connections and SOCKS listeners. A configurable combined capacity bounds pending
direct dials and active direct/SOCKS connections; excess direct dials return
ErrCapacity. ServeSOCKS takes ownership of the supplied listener. Configure once
with ClientConfig before concurrent use. Optional endpoint failover, CA/SNI/pin,
TLS backend, XHTTP route, receive profile, setup timeout and padding are available.
Advanced cluster/bond administration stays in the CLI/internal implementation in
this initial SDK; it is not falsely represented as a stable complete control API.

`NewServer(ServerConfig)` returns http.Handler. The host application owns TLS
certificates, TLS 1.3, HTTP/2 setup, public listener admission and graceful shutdown.
The public handler rejects plaintext/older TLS. Target private-address access is
disabled by default; tests explicitly opt in for loopback. Authentication and
bounded tunnel admission remain in the core. No custom cryptography is added.

See [examples/embed](../../examples/embed/main.go) for http.Transport.DialContext
integration. [integration/external](../../integration/external/) is a **separate Go
module**, tested in CI, that cannot import internal packages and performs a real
TLS/XHTTP echo using only this public API. Root external-package tests cover five
transports, Go/NSS, padding, upload half-close, setup-context cancellation,
deadline reset, client shutdown, capacity and SOCKS ownership.

Experimental NSS preferences: `TLSClientProfile: foxtunnel.TLSClientFirefox158`
(NSS 3.130 only), separately `HTTP2ReceiveProfile: foxtunnel.HTTP2ReceiveFirefox158`.
The local profile is applied before streams and retained in identity pools.
[Measurements and limits](../research/MOZILLA-CLIENT-PROFILE.en.md).
