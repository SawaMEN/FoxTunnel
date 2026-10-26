# Necko in the main CLI and SDK

The Linux amd64 main CLI and Go SDK now support `Engine: "necko"`. They verify
the distribution, start one owned xpcshell process, wait for readiness and join
it on shutdown. A separate manual launcher is no longer required. TLS, HTTP/2,
HTTP/3 and QUIC remain in Mozilla; the Go adapter handles local IPC only.

Stage 1 is qualified on Linux amd64 at helper commit `290923c` using source
build [40129737449](https://github.com/SawaMEN/FoxTunnel/actions/runs/40129737449).
The packaged native gate passed three consecutive runs in
[40133136426](https://github.com/SawaMEN/FoxTunnel/actions/runs/40133136426).
The six-step qualification record below defines the supported scope.

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

Qualified native carriers are H2/H3 TCP CONNECT, H2 POST and all three XHTTP
modes. H2 UDP v1/v2, Multi-Node, Bond RPC/persistent lanes, authenticated discovery,
configured fallback origins and new-connection balancing use the native HTTP
adapter. Padding and strict FoxTunnel negotiation are supported on H2 POST and
XHTTP; raw CONNECT rejects them because it cannot carry their extension headers.

H3 POST/UDP/Bond, SPKI/SNI overrides, per-node pins, native ARM64 and manual
TLS/QUIC/HTTP profiles remain outside this qualification and are rejected where
applicable. Hostname and certificate-chain checks remain in NSS. Additional CA files are supported. Setup time is 100 ms through
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
DATAGRAM. UDP stream-v2 is provided by the separate adapter below. Native H2
streaming, Bond and XHTTP are now qualified; H3 UDP remains a later stage.

### Qualified native H2 UDP v2 bridge

The private `OpenUDPStream` adapter now requests a single native H2 POST to
`/.well-known/foxtunnel-udp-stream-v2`. Authenticated IPC command `0xf1` receives
an acknowledgement only after native H2 response headers; following bytes are
BE16-framed RFC1928 packets. Both directions validate complete packets and stop
reading while downstream writes are pending. Async upload/download pipes are
bounded to two 32 KiB segments. Closing or canceling the flow closes its IPC
socket and aborts the native channel; remote errors never select Go HTTP.

`UDPStreaming` and `UDPMultiNode` are enabled for the qualified native H2 path.
`TestGeckoManagedUDPStream` passed three times with headers before any upload,
4096 maximum-size binary frames on one request, concurrent upload/download,
a delayed reader and cancellation. `TestGeckoManagedUDPMultiNode` passed both
control-close and node-loss cases three times. Ordinary tests still skip native
gates without the verified bundle; Node codecs and Go routing fixtures do not
stand in for Mozilla networking. H3 UDP remains outside this qualification.

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
Finite and unbounded bodies both use the native streaming-body replay guard.
Finite buffers retain an explicit validated Content-Length; this prevents native
POST replay after an ambiguous connection loss without changing wire length.
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

Overall completion: **2 of 6 stages complete** (stages 1 and 2).

Stage 2: **4 of 4 checks complete**, qualified at helper commit `b5d86cc` in
[native runtime run 40224778052](https://github.com/SawaMEN/FoxTunnel/actions/runs/40224778052)
using compiled source run `40199106358`. CLI/SDK gates passed three times,
all seven managed resource modes passed, and both 300-second CONNECT and paired
baseline/current gates passed. The [sustained-resource record](validation/endurance/README.md)
retains raw samples, source hashes, limits and qualification details.

1. Fix native streaming: duplex HTTP, UDP v2/multi-node, Bond lanes, XHTTP.
2. Pass the full CLI/SDK matrix and sustained resource gates.
3. Qualify H3 POST/UDP, including no-TCP-fallback tests (draft in xfd-h3).
4. Build and qualify native Necko on ARM64.
5. Implement the remaining native SNI/SPKI/profile settings.
6. Verify and package the unified NSS + Necko distributions.

Stage 1 progress: **6 of 6 steps complete and natively qualified**:

- Done: reproduce and trace the headers-before-body deadlock on the compiled
  source artifact from run 40118209336 (archive SHA256
  864d7e3f7540437852fbfa23714750b363dd3d2e2292ad9c9f762e377ee7dfa2).
- Done: implement opt-in early final-response-header delivery, with exact pinned
  source patches, source hashes, helper wiring and a native regression.
- Done: duplex HTTP and header-only response/EOF/cancellation qualification (3 passes).
- Done: UDP v2 and Multi-Node native stress/transfer/teardown qualification (3 passes).
- Done: Bond persistent lanes and discovery/active-path-loss qualification (3 passes).
- Done: all XHTTP modes and the integrated CLI/SDK matrix (3 passes).

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
channels do not enable the option. The API compiled in source run 40129737449
and passed the packaged native regressions in run 40133136426.

Run 40119674183 confirmed native CONNECT/half-close/trust, launcher transfer,
Bond RPC/discovery and standalone XHTTP packet-up/stream-one, but failed duplex
HTTP, UDP v2/multi-node, Bond lanes and stream-up. Its integrated packet-up SDK
case also failed at that checkpoint; the qualified build fixes that regression.

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
subsequently passed three times on the new source build in run 40133136426.

The native Multi-Node gate now runs both SOCKS-control closure and single-exit
loss after binary UDP transfer. Each case requires both remote stream handlers
to finish while the client/helper remain alive, so whole-client shutdown cannot
hide a leaked association. Exit loss must also close the SOCKS control socket,
with no stream reopening or silent migration of existing UDP flows. These new
native lifecycle cases passed three times on the early-response-header build.
Ordinary routing fixtures alone do not qualify them.

The native Bond outage gate now cancels a body on an actually established lane
before the second binary transfer, and rejects subsequent requests to that
exit. It records active lanes and requires at least one real lane interruption;
returning 503 only for new requests would not test persistent-path loss. The
RPC cases retain first-origin rejection. Both explicit topology and discovery
must preserve the same connection's binary data through the outage. Native
qualification of this stronger lane gate passed three times in run 40133136426.

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


### Stage 1 final native qualification

The final helper/CLI/SDK code is commit `290923c3686fca93e384941e5da77ee1a0604647`.
Source run `40129737449` compiled the exact pinned Gecko revision and patches
from commit `1e2544743825d485e972fd5248039cc328184b32`; runtime artifact
`12576165741` has archive SHA256
`7bb3bfd3f090eaaf030563f2c9c7a482d7b76847ea44418a32bc975c2f30a253`.
The runtime workflow verified its source lock/provenance and binary hashes before
packaging and executing the main CLI and SDK.

The mandatory native gate ran `go test -race . ./experiments/firefox-necko`
with the IntegratedNecko/GeckoManaged IPC/UDP/HTTP/Bond/XHTTP filter,
`-count=3 -timeout=600s`. All three runs passed for each required stage-1 group:

| Step | Confirmed result |
| --- | --- |
| 1. Diagnose | Native headers-before-body deadlock reproduced and traced. |
| 2. Fix | Early-header C++ API compiled; bounded native upload/download bridge wired. |
| 3. HTTP | Duplex, delayed/empty response body, cancellation, and no POST/UDP-v1 replay. |
| 4. UDP | 4096 frames per run, Multi-Node transfer, control close and exit loss. |
| 5. Bond | RPC/lanes, explicit/discovered topology, adaptive routing and an interrupted active lane. |
| 6. XHTTP/CLI/SDK | stream-one, stream-up, packet-up; H2 POST; padding/strict, capacity and ownership. |

Supplementary native GET/trust, alternate-origin/outage, fixed-length upload,
small interactive response and HTTP CONNECT tests passed in the workflow's
research-runtime step. They intentionally skip in the later bundle-only step;
none of the mandatory stage-1 groups above was skipped. The workflow also passed
Firefox wire comparisons, launcher H2/H3 transfer/SIGTERM and resource gates.
These results do not establish DPI indistinguishability or qualify H3 POST/UDP,
ARM64 Necko, or the remaining identity/profile options.

The separate distribution pipeline `40133136488` passed NSS amd64/ARM64, Neqo
and its Necko runtime job, but unified-archive indexing failed with
`ValueError: unsafe archive member` in `merge_necko_nss.py`. Release archive
assembly remains stage 6; no unified release is claimed by stage-1 completion.


### Stage 3 qualified: native H3 HTTP and UDP

Stage 3 is complete: **4 of 4 steps**, **3 of 6 stages overall**.
Qualified code is `7d4eee64c0acd83daefdaa4c3bd8ab87558bb247` on top of the
stage-2 baseline. The native C++ build at `bee2e2d` passed in source run
[40234429164](https://github.com/SawaMEN/FoxTunnel/actions/runs/40234429164).
Runtime run [40234867279](https://github.com/SawaMEN/FoxTunnel/actions/runs/40234867279)
verified that exact source lock and binary hashes before running the packaged
CLI and SDK. The retained [acceptance record](validation/h3/acceptance.json)
binds these runs to source/helper hashes and artifact digests.

1. Preserved all stage-2 ownership, replay, failure-category and GC fixes;
   validated all 22 combined patches against the pinned Gecko source.
2. Compiled the native HTTP3-only API and integrated H3 POST, UDP v1/v2,
   Multi-Node and Bond in the helper, CLI and SDK.
3. Passed 13 mandatory native groups three times each, including H3 duplex,
   certificate trust and zero-TCP tests, plus H2 replay, truncation, headers,
   XHTTP and ownership regressions. Five supplementary research-runtime groups
   passed in their research step and intentionally skip in the bundle-only step.
4. Passed all 12 managed workload modes for 60 seconds plus 6 seconds settling,
   H2/H3 CONNECT for 300 seconds each, wire measurements and paired controls.
   Every H3 managed mode selected protocol 3 and counted zero TCP origin accepts.
   All resource bounds and process/profile cleanup checks passed.

The privileged parent-process API selects the HTTPS origin's native H3 route
without Alt-Svc discovery. Channel/transaction policy prohibits TCP fallback and
preserves NSS trust and hostname checks. Negative tests use TCP-only origins and
cover GET, POST and both UDP versions; positive HTTP and sustained H3 workloads
also reject speculative TCP connections. Bond outage tests close the actual TCP
or QUIC origin connection.

Evidence and limits are described in [the H3 qualification record](validation/h3/README.md).
Resource figures cover the helper on loopback; they do not establish WAN speed,
whole-client memory, statistical improvement or DPI equivalence. The wire
comparison covers native CONNECT, not a new POST/UDP-specific fingerprint claim.
ARM64 Necko, remaining identity/profile settings and unified release archives
remain stages 4 through 6. `main` is unchanged.

### Stage 4 qualified: native Linux ARM64

Stage 4 is complete: **4 of 4 steps**, **4 of 6 stages overall**.
Qualified implementation: `24d74d081f209ba931b70500d8ba407c54fe83cf`.
Both native source jobs passed in
[run 40264186586](https://github.com/SawaMEN/FoxTunnel/actions/runs/40264186586),
and both full runtime qualification jobs passed in
[run 40264186589](https://github.com/SawaMEN/FoxTunnel/actions/runs/40264186589).
[General CI 40264186549](https://github.com/SawaMEN/FoxTunnel/actions/runs/40264186549)
also passed. The [acceptance record](validation/arm64/acceptance.json) binds the
exact source/helper hashes, platforms, tests and resource reports; see the
[qualification evidence](validation/arm64/README.md).

1. Built the pinned Gecko revision and all 22 combined patches independently
   on native Linux amd64 and ARM64 runners.
2. Verified architecture-specific provenance, source/runtime hashes and actual
   ELF machines; packaged and executed the native launcher and main CLI.
3. Passed 13 mandatory native groups three times on each architecture, with
   no mandatory skips: H2/H3 CONNECT and POST, UDP v1/v2, Multi-Node, Bond,
   XHTTP, CLI/SDK, trust, no-TCP fallback, replay, truncation and half-close.
4. Passed all 12 managed modes on each architecture (60 seconds plus 6 seconds
   settling), H2/H3 CONNECT (300 seconds per protocol), paired baseline/current
   controls and same-runtime Firefox observations. Raw resource and cleanup
   reports were independently verified; both paired reports reproduced exactly.

The source lock lists both platforms. Provenance records the actual build
architecture, artifact selection requires its matching runtime/provenance pair,
and bundle verification rejects mixed ELF machines even after rehashing. The
entire ARM64 package was independently checked: 8267 manifest files and 122
ARM64 ELF binaries. The source runtime archive's 119 ELF files were also audited.
CLI/SDK auto-selection and build metadata recognize native ARM64 Necko.

All 24 managed reports passed final RSS-growth (192 MiB after idle settling),
descriptor (idle plus 16), process join and profile removal checks. All five
managed H3 modes on each architecture recorded protocol 3 and zero TCP accepts.
Sampled RSS peaks are retained. These are helper-only loopback measurements,
not whole-client memory, WAN throughput or statistically significant speedups.
The controlled CONNECT wire audit retains inconclusive randomized TLS extension
order/JA3 differences; it does not establish DPI equivalence or a POST/UDP
fingerprint match.

A local `TestNativeSetupTimeout` failure was also reproduced on the unchanged
stage-3 baseline; the candidate's general CI and both native qualification jobs
passed. This stage does not claim to fix that pre-existing intermittent test.
The complete prior 2/4 checkpoint is retained under
[checkpoint-2of4](validation/arm64/checkpoint-2of4/README.md).

SNI/SPKI/profile overrides and unified NSS + Necko release archives remain
stages 5 and 6. Linux ARM64 Necko does not qualify the separate Neqo Rust FFI
bridge or Android/macOS Necko. `main` is unchanged.

### Stage 5 candidate: native identity and profile policy

Stage 5 progress: **1 of 4 steps confirmed**; overall completion remains
**4 of 6 stages**. Work is isolated on `xfd-identity`, based on the qualified
stage-4 tree. The new 28-patch source lock is a candidate until rebuilt and
qualified on both native architectures. No promotion to `xfd` is claimed yet.

1. Done: identify trust, origin scope, session/coalescing and profile boundaries.
2. Candidate implementation: primary SNI/SPKI, bounded native TLS/H2 presets,
   immutable policy registration and CLI/SDK wiring. Per-node pin-file support
   remains explicitly rejected while its managed-policy integration is pending.
3. Pending: rebuilt native positive/negative trust gates and wire measurements.
4. Pending: native CLI/SDK, amd64/ARM64 regressions, evidence and qualification.

A helper-only parent-process API registers an immutable policy for each native
route before any socket can be opened to it. Installing a policy after an
unprotected connection, changing a registered policy, invalid pin/DNS inputs
and unbounded registration fail closed. Ordinary Firefox connections do not
activate this registry. Policy-enabled TCP sockets disable cache, tickets and
early data; native QUIC excludes policy-enabled connections from token use and
storage. Coalescing into or out of policy routes is rejected. ECH public-name
verification cannot replace the configured identity hostname.

SNI changes the NSS/QUIC server name and certificate hostname, preserving the
network route and HTTP authority. The leaf SPKI SHA-256 check runs after normal
PKI verification and before NSS/QUIC completes authentication. Pin failure is
terminal and is not an override or a retryable outage. The primary identity is
not inherited by alternate origins. A helper's identity/preset settings are
immutable after construction; later low-level setters cannot silently drop them.

The `firefox-158` TCP TLS preference preset selects measured groups, key shares
and signature preferences in the pinned native NSS and requires TLS 1.3. Its H2
receive preset explicitly selects measured HPACK, connection and stream windows.
The name denotes a parameter preset, not the Firefox 158 executable or full
fingerprint parity. TCP/H2-specific presets are rejected for H3. Defaults retain
the pinned runtime's native settings.

Candidate tests exercise SNI without an IP SAN, HTTP authority preservation,
correct and incorrect pins, hostname and CA failures before application requests,
CONNECT/POST/UDP v1/v2, alternate-origin isolation, measured TLS/H2 parameters and
main CLI/SDK automatic engine selection. These tests require the new verified
bundle; their skips without it are not native qualification. Local Go race and
JS/parser checks and exact patch application are preparatory evidence only.
