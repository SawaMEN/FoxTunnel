# Necko in the main CLI and SDK

The Linux amd64 main CLI and Go SDK now support `Engine: "necko"`. They verify
the distribution, start one owned xpcshell process, wait for readiness and join
it on shutdown. A separate manual launcher is no longer required. TLS, HTTP/2,
HTTP/3 and QUIC remain in Mozilla; the Go adapter handles local IPC only.

## Main CLI

The runtime CI package includes both `foxtunnel` and the standalone
`foxtunnel-necko`, the complete native runtime and integrity metadata.

```sh
export FOXTUNNEL_USER='your-user'
export FOXTUNNEL_PASSWORD='your-password'
./foxtunnel client --engine necko --transport h3-connect \
  --server https://proxy.example.com --listen 127.0.0.1:1080
```

The main executable discovers its enclosing bundle by default. If the binary
is installed elsewhere, add `--necko-bundle /absolute/path/to/verified-bundle`.
Use `h2-connect` for HTTP/2; explicit H3 has no fallback. Existing connection
links can be combined with `--engine necko --necko-bundle ...` when their carrier
is H2/H3 CONNECT. `--events-json` continues to emit main-CLI process events;
helper stdout and raw Gecko diagnostics do not contaminate that protocol.
SIGTERM, Ctrl-C and `--shutdown-on-stdin-eof` stop and join the helper.

## SDK

```go
client, err := foxtunnel.NewClient(foxtunnel.ClientConfig{
    Engine: "necko",
    NeckoBundle: "/opt/foxtunnel/version-1",
    ServerURL: "https://proxy.example.com",
    Credentials: foxtunnel.Credentials{Username: user, Password: password},
    Transport: "h3-connect",
})
if err != nil { return err }
defer client.Close()
conn, err := client.DialContext(ctx, "tcp", "example.org:443")
```

Construction starts the helper and waits for bounded readiness. SDK setup
context cancellation does not terminate an already established stream. Returned
connections retain deadlines and `CloseWrite`; `Client.Close` cancels pending
work, closes owned streams and joins the helper before removing its profile.
The normal SDK connection limit, SOCKS listener ownership and status API apply.

## Policy and ownership

The private helper listener uses a fresh 128-bit random password in the owner's
0600 temporary configuration. It refuses anonymous SOCKS and incorrect passwords.
Its password is never placed in argv, process events or status. This keeps the
helper port from bypassing main-CLI local SOCKS authentication.

Unsupported policy is rejected: UDP, padding, Bond/discovery, fallback servers,
balancing, XHTTP, SPKI/SNI overrides, strict FoxTunnel draft negotiation and
manual TLS/QUIC/HTTP profile overrides. Hostname and certificate-chain checks
remain in NSS. Additional CA files are supported. Setup time is 100 ms through
120 seconds; the default is 15 seconds. Native idle/drain limits still apply.
Legacy and NSS/Neqo `mozilla` selections remain explicit independent engines;
`necko` requires the verified Linux amd64 runtime, without native Go build tags.

## Firefox comparison

The comparison now includes an independent control: two fresh full Firefox
processes use the same pinned libxul, proxy, trust and binary CONNECT workload.
Raw differences are retained, including order, frame lengths and HPACK hashes.

In the final CI repetitions, managed FoxTunnel versus Firefox had raw H2
HPACK/HEADERS and frame-order differences in 1/3 runs. The standalone helper had
them in 3/3 runs; Firefox versus Firefox had them in 2/3 runs. Decoded headers
agreed throughout. All three comparisons had extension-order/JA3 differences in
3/3 H3 runs, with matching extension sets. Thus exact byte equality between
separate sessions is not a Firefox invariant. These small samples do not establish
equality of distributions.

The pinned Mozilla implementation marks an HPACK size update pending when peer
SETTINGS arrive (`Http2Session::RecvSettings` and
`Http2Compressor::SetMaxBufferSize`). Whether SETTINGS ACK precedes the first
HEADERS affects which block contains that update. Attribution of the observed three-byte
HPACK difference to that update is consistent with the source and ACK ordering;
the observation files retain hashes rather than a raw HPACK instruction dump.
Forcing a fixed order or
turning off H3 extension randomization would replace Mozilla's behavior with a
custom deterministic profile. This integration leaves that behavior intact.
No DPI indistinguishability claim is made.

CI retains standalone, managed-engine and Firefox-self observations separately.
It verifies actual main-CLI and SDK binary transfers, half-close, setup-context
cancellation, capacity, owned shutdown, private IPC authentication and cleanup.
See the [integration validation record](validation/integration/README.md) for the
exact tested commit, retained observations and CI run.


## xfd development: native UDP v1 via H2

The first extension to the native Necko engine is an authenticated, bounded
single-datagram IPC operation that posts the existing `udp-v1` wire packet
through Gecko's own H2/TLS stack. The local UDP ASSOCIATE socket and reply
source checks remain owned by FoxTunnel Go. It is deliberately not QUIC
DATAGRAM or UDP stream-v2. Necko H3 UDP, streaming, Bond, balancing and XHTTP
remain unimplemented. Do not enable those options with forced Necko.

### Experimental UDP v2 bridge (not enabled in client configuration)

The private `OpenUDPStream` adapter now requests a single native H2 POST to
`/.well-known/foxtunnel-udp-stream-v2`. Authenticated IPC command `0xf1` receives
an acknowledgement only after native H2 response headers; following bytes are
BE16-framed RFC1928 packets. Both directions validate complete packets and stop
reading while downstream writes are pending. Async upload/download pipes are
bounded to two 32 KiB segments. Closing or canceling the flow closes its IPC
socket and aborts the native channel; remote errors never select Go HTTP.

`UDPStreaming` remains rejected by normal Necko client configuration pending
native validation. `TestGeckoManagedUDPStream` checks response headers before
any upload, 4096 maximum-size binary frames on one H2 request with concurrent
upload/download and a delayed reader to exercise bounded-pipe backpressure,
and cancellation. The runtime workflow explicitly includes this test in its
packaged native gates; ordinary Go tests skip it without the verified bundle.
This gate requires `FOXTUNNEL_NECKO_BUNDLE`; Node codec/pump tests alone do not
establish that the pinned Gecko streams unknown-length uploads. Long-session,
load and runtime compatibility validation are still required before enabling
this path. Native H3 UDP, XHTTP and Bonding remain pending.


### Native streaming upload normalization fix

The first mandatory UDP-v2 native gate failed at response-before-upload setup
in runtime CI run 40110073711 (commit 6316640). The pinned Gecko revision has a
Fetch streaming-upload path, but `explicitSetUploadStream(..., -1, ...)` alone
normalizes an async pipe into a StorageStream and waits for EOF before sending
the request. A live session cannot reach EOF before receiving its setup ACK.

The source lock now includes `enableStreamingUpload()` on the privileged
`nsIHttpChannelInternal` interface. It must be called on the main thread before
opening the channel or attaching its upload stream. It opts into Gecko's existing
Fetch streaming path; ordinary uploads still use normalization. The helper calls
it before attaching the bounded async upload pipe and still disables redirects
and interactive authentication. Missing API support fails closed.

This changes libxul and its XPCOM interface, so the old binary is incompatible
with UDP v2. Source builds now run on xfd as well as firefox, and runtime selection
searches matching source locks across branches. The native duplex gate must pass
against the newly compiled runtime before UDPStreaming is enabled in CLI/SDK.
