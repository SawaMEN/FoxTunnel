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

### Authenticated native HTTP adapter in xfd

The private command `0xf2` carries bounded JSON request metadata (16 KiB) and
independently framed upload/response bodies (32 KiB maximum chunks, explicit EOF
and native-error termination). It is available only with the helper's random IPC
secret. HTTPS origins are checked against explicit client configuration or an
authenticated discovery snapshot before dispatch. TLS, certificate verification,
public HTTP framing and sockets remain owned by Gecko. No Go HTTP fallback is
installed if the native adapter is missing or fails. One helper serves all trusted
origins; each CONNECT channel receives its own selected proxy, without a global
proxy-switch race. Ordinary POST/GET requests bypass the system proxy.

The adapter is wired into H2 POST, all three XHTTP carriers, UDP stream-v2,
UDP multi-node, static/adaptive Bond (RPC and persistent lanes), discovery and
new-connection balancing. XHTTP's inner FoxTunnel HTTP/2 envelope is still an
application protocol implemented in Go; its outer HTTPS carrier uses Mozilla.
Padding and strict draft negotiation can use H2 POST or XHTTP; the existing raw
CONNECT handoff cannot forward their extension headers and rejects those options.
H3 CONNECT can use the new adapter for TCP; H3 POST/UDP HTTP channels, manual
SNI/SPKI overrides, per-node pins and native ARM64 packaging remain unsupported.

Validation is split deliberately:

- Local Go IPC and routing tests cover response-before-upload, binary framing,
  truncation, explicit native errors, cancellation, owned shutdown, all three
  XHTTP modes with padding/strict negotiation, adaptive Bond and UDP multi-node.
  The routing fixtures use Go peers and do not qualify Mozilla networking.
- Native research tests against source-build artifact `12501945687` passed H2/H3
  CONNECT transfer/half-close through command `0xf2`, standalone handoff and trust
  rejection. That older runtime does not contain the new streaming upload API.
- The runtime workflow now includes `TestGeckoManagedHTTP`,
  `TestGeckoManagedBond` (RPC/lanes, discovery, adaptive scheduling and path loss),
  UDP v1/v2 through the public SDK, all three XHTTP modes and H2 POST through the
  packaged CLI/SDK, and padding/strict negotiation. These require the new source
  build and must pass before any native POST/XHTTP/Bond support is qualified.

Source build `40111523804` was still compiling when this implementation block
was prepared. No native POST qualification or complete parity claim is made by
unit-test success alone.


Native HTTP GET regression: the older verified research runtime also exercises
1 MiB GET download and alternate-origin CA rejection through command `0xf2`.
Gecko may coalesce more than 32 KiB into one onDataAvailable callback. Both native
stream listeners now accept at most 1 MiB for that callback, consume it before
returning, and suspend delivery while the 64-KiB pipe drains. IPC readers and
writes still use 32-KiB frames. An oversized callback fails closed rather than
allocating an unbounded buffer. This fixes the native-only GET abort exposed by
the larger-response gate; unit peers did not reproduce that delivery shape.


### Native finite uploads and packet-up qualification

Known HTTP bodies up to 1 MiB are collected from bounded IPC frames, checked
against their declared length and uploaded using `nsIArrayBufferInputStream`.
They do not need the streaming-upload API; unbounded bodies still require it.
The first explicit request-header value replaces Gecko's default header; further
values merge. This preserves XHTTP's exact Content-Type rather than appending it
to the default upload MIME type. The adapter invokes `httptrace.WroteRequest`
once the complete body has been copied into IPC transport ownership (or with its
copy error). XHTTP uses that boundary before releasing/reusing packet storage.
It is not a measurement of remote receipt or an application ACK.

Research gates on source artifact `12501945687` now passed native finite POST
binary upload/headers, 1-MiB GET, interactive small GET delivery, alternate-origin
selection with separate CA roots, terminal CA rejection versus retryable network
outage, adaptive Bond RPC with discovery and first-path loss, and XHTTP packet-up
with a custom Path/Host, padding, strict negotiation, detached setup context and
binary half-close. These native tests run with `FOXTUNNEL_XPCSHELL`; persistent
lanes, UDP v2/multi-node, H2 POST and XHTTP streaming still require the rebuilt
API and packaged-bundle gates. Ordinary fixtures never stand in for those gates.

Source build `40111523804` failed because the new XPCOM method lacked an explicit
HttpBaseChannel.h override declaration. Commit 79b7e08 adds that declaration and
its pinned source hash; the replacement source build is required for streaming
qualification. Multi-root test certificates also use unique issuer/serial
identities, so loading two independent roots into NSS does not fail before the
multi-node test reaches the network.

The HTTP channel also sets a binary Content-Type hint before opening. An untyped
peer that flushes headers before the first body byte must not wait for Gecko's
MIME sniffer. A native interactive GET regression verifies immediate delivery
without a response Content-Type; typed server responses keep their own MIME type.

### xfd completion plan and response-header deadlock

Overall completion: **0 of 6 remaining stages complete**.

1. Fix native streaming: duplex HTTP, UDP v2/multi-node, Bond lanes, XHTTP.
2. Pass the full CLI/SDK matrix and sustained resource gates.
3. Qualify H3 POST/UDP, including no-TCP-fallback tests (draft in xfd-h3).
4. Build and qualify native Necko on ARM64.
5. Implement the remaining native SNI/SPKI/profile settings.
6. Verify and package the unified NSS + Necko distributions.

Stage 1 progress: **2 of 6 steps implemented; native validation pending**:

- Done: reproduce and trace the headers-before-body deadlock on the compiled
  source artifact from run 40118209336 (archive SHA256
  864d7e3f7540437852fbfa23714750b363dd3d2e2292ad9c9f762e377ee7dfa2).
- Done: implement opt-in early final-response-header delivery, with exact pinned
  source patches, source hashes, helper wiring and a native regression.
- Pending: duplex HTTP and header-only response/EOF/cancellation qualification.
- Pending: UDP v2 and Multi-Node native stress/transfer qualification.
- Pending: Bond persistent lanes and discovery/path-loss qualification.
- Pending: all XHTTP modes and the integrated CLI/SDK matrix.

The compiled streaming-upload API bypasses upload normalization correctly:
the native log shows request HEADERS transmitted and HTTP/2 200 response headers
parsed immediately. However, nsHttpTransaction's response pipe contains body
bytes only. Its nsInputStreamPump does not start until body data or closure, so
the JS listener never observes a headers-only response while both endpoints
wait for upload data. A Content-Type hint alone cannot fix this pipe wakeup.

The new parent-process `deliverResponseHeadersEarly` opt-in publishes final
headers through the existing serial transport-sink proxy after native HTTP
reset/retry decisions. The channel wakes its pump's start state without writing
synthetic payload bytes. An empty, open response pipe remains readable later;
only actual pipe closure ends the body. Suspension, cancellation and the normal
single OnStartRequest state transition remain owned by the pump. Ordinary
channels do not enable the option. This is a source change awaiting compilation
and native regression results, not a completed streaming qualification.

Run 40119674183 confirmed native CONNECT/half-close/trust, launcher transfer,
Bond RPC/discovery and standalone XHTTP packet-up/stream-one, but failed duplex
HTTP, UDP v2/multi-node, Bond lanes and stream-up. Its integrated packet-up SDK
case also failed and remains an independent regression to investigate.

The packet-up SDK failure has a separate admission cause: the integrated SDK
sets MaxConnections=1 to test the logical tunnel limit, but Plan.Apply forwarded
it as the helper's native-operation limit as well. Packet-up needs a long-lived
GET plus POST operations, so its own upload was rejected. The factory now keeps
the helper's independent bounded default (256 native operations), while the
existing SDK/SOCKS admission gate still rejects a second logical connection.
Native admission regression result: the integrated packet-up matrix passed
three consecutive times with the factory correction (12/12 subtests: SDK,
SDK-auto, SDK-padding-strict and packaged CLI). The SDK case uses a logical
limit of one, transfers a binary payload and still rejects a second logical
connection. This isolated qualification used a checkout of be2ea71 plus only
the factory correction, packaged against the verified source runtime from
40118209336 and its original matching source lock/provenance. No old runtime
was relabeled as containing the early-response-header API. The complete matrix
must still pass again on the new source build.

The native Multi-Node gate now runs both SOCKS-control closure and single-exit
loss after binary UDP transfer. Each case requires both remote stream handlers
to finish while the client/helper remain alive, so whole-client shutdown cannot
hide a leaked association. Exit loss must also close the SOCKS control socket,
with no stream reopening or silent migration of existing UDP flows. These new
native lifecycle cases await the early-response-header source build; passing
ordinary routing fixtures does not qualify them.

The native Bond outage gate now cancels a body on an actually established lane
before the second binary transfer, and rejects subsequent requests to that
exit. It records active lanes and requires at least one real lane interruption;
returning 503 only for new requests would not test persistent-path loss. The
RPC cases retain first-origin rejection. Both explicit topology and discovery
must preserve the same connection's binary data through the outage. Native
qualification of this stronger lane gate remains pending.

The packaged CLI/SDK/native streaming gate requires three consecutive passes
with the race detector (600-second suite deadline). This includes the native
HTTP headers-only/duplex cases, 4096-frame UDP stress, both Multi-Node teardown
triggers, Bond RPC/lanes/discovery/outage, and every integrated XHTTP mode. A
single successful transfer does not close stage 1.

### Native finite POST replay policy

A native regression primed an H2 connection with GET, consumed a finite POST
on the server, then closed the actual TCP connection before any response headers.
Gecko's default reused-connection recovery replayed the POST ten times. A nil
Go GetBody does not prevent replay inside Gecko's cloneable native body stream.
Finite POST/UDP bodies now use Gecko's existing streaming-body replay guard,
even when the actual input is an owned fixed ArrayBuffer. The helper supplies
the exact validated Content-Length explicitly, so these bodies retain their
finite wire framing. Once any request bytes were consumed, native Restart
fails instead of rewinding and replaying the body. Unknown-length uploads
already use the same guard. Safe GET recovery and CONNECT setup retain their
existing native behavior.

The regression then passed three times with exactly one consumed POST and one
TCP accept; the native fixed-upload test also retained the exact length and
binary payload. This isolated before/after check used the verified source
runtime from 40118209336 and a matching research helper. It does not qualify
the pending early-response-header C++ API. TestGeckoManagedHTTPNoReplay also
runs in the packaged three-pass native gate.

The UDP-v1 IPC response now half-closes its output and waits for the caller's
socket close before retiring the transport. An async native write can complete
while response bytes are still queued; immediate transport abort occasionally
lost a valid reply. The native no-replay gate warms the same operation type
(HTTP or UDP-v1), then cuts the TCP connection after consuming its next POST.
Both cases passed ten times (20/20 checks), with one consumed POST and no retry
connection. CONNECT, certificate rejection, H2/H3 outage recovery and the
packaged CONNECT/packet-up CLI/SDK matrix also passed with the per-body policy.
