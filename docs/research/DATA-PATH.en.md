# Stage three: bounded persistent bond channels

[Русский](DATA-PATH.md) | **English**

Built on the stage-two Mozilla profile branch (PR #13), without changing its TLS
policy or release targets. Linux amd64/arm64 NSS remains the published matrix.
This change concerns the explicit experimental `--bond` mode. Ordinary CONNECT
and packet-up retain their implementations.

Opt in locally with `foxtunnel client --link-file connection.txt --bond-lanes`;
the link must already enable bond, or add `--bond` explicitly. Discovery works
with this option too. Plain `--bond` retains RPC because measured bulk relay
throughput regressed in some workloads. The client-only flag is not serialized
into links/setup/server JSON. Internal `bond.Client.PersistentLanes` defaults
to false.

## Protocol and compatibility

A successful legacy session open advertises
`X-FoxTunnel-Bond-Lane: records-v1`. Updated relays forward that capability.
Without it the client uses the original per-record RPC. New clients also detect
a relay that omits the lane capability on a particular entry, before sending any
operation record, and use legacy RPC on that entry. TLS, authentication, hub
identity and malformed-record errors never trigger that compatibility fallback.
Old clients still send the original requests to an updated hub.

A lane is one authenticated duplex POST to the existing bond path. It binds to an
**existing** session with its 32-byte token and pinned hub identity; it cannot open
or retarget a destination. Session open/close remain legacy RPC operations.
Every request on a lane has this big-endian format:

| Field | Bytes | Rule |
|---|---:|---|
| Record length | 4 | 49 through 49 + 32768 |
| Poll wait, milliseconds | 4 | Clamped to 20–1000 for this record |
| Original operation/token/sequence/ACK header | 49 | Same session token; write/read/FIN only |
| Payload | 0–32768 | Original operation validation applies |

The reply contains a two-byte status, four-byte payload length (at most 32768),
and that payload. There is exactly one outstanding exchange per lane. The client
reuses a bounded pool across entries and both directions. The original stream
sequence numbers, cumulative download acknowledgements, destination-delivery
acknowledgements and duplicate handling remain authoritative.

Temporary H2/H3 stream cancellation/internal/rejection errors can retry the same
idempotent record within the existing three-sweep bound. Protocol errors,
CA/SNI/pin failures and HTTP authorization/hub errors remain terminal. A lost ACK
cannot redial the destination or append that record twice. The common exit is
still a single point of failure; no exit-socket migration was added.

## Queues, small writes and copies

A client holds at most eight upload slots and eight receive slots, each 32 KiB.
Negotiated channels add one 32 KiB small-write accumulator, up to 16 persistent
HTTP streams, and one at-most-32825-byte send buffer per channel. A small write
is flushed when full or after a 1 ms timer; this is a batching budget, not a
real-time scheduling guarantee. `CloseWrite` flushes it and waits for destination
ACKs before FIN. Large blocks bypass that accumulator. Legacy RPC keeps its
previous write behavior.

The hub admits at most 16 lanes per session. The original eight-block upload and
download windows remain, with one possible EOF marker. Each lane also temporarily
owns one bounded input frame and a reusable reply buffer. A download reply is
copied while the session lock protects the receive slot: another lane's ACK must
not recycle it during transmission. The client reads replies into its existing
receive slots. Request headers and payloads are buffered together into one lane
write. Relays copy/flush complete bounded reply records instead of every arbitrary
transport read. These are intentional copies, not a zero-copy implementation.

HTTP/TLS/kernel buffers and concurrent retry records add memory beyond the data
windows. Relays retain one at-most-32774-byte response buffer per lane. The server
`--max-tunnels` limit counts active HTTP handlers, including each persistent lane;
it is not a count of logical bonded sessions. The default is 256. A deployment
must budget enough handlers for its simultaneous lanes and control requests.
Idle lane bodies and sessions expire after two minutes. Cancellation closes the
pipes/bodies and joins active exchanges before a caller's upload slot is reused.

The NSS payload bridge already passes bounded Go slices to synchronous C calls;
it does not use `C.GoBytes` on every payload. The certificate path does copy DER.
This stage changes batching/HTTP overhead, not NSS cryptography or the bridge ABI.
The benchmark reports whole-process `runtime.NumCgoCall` deltas; CPU pprof shows
Go/runtime/cgo boundaries, not complete native NSS stacks or native allocations.

## Measurements and reproduction

[Raw measurements and interpretation](../measurements/2026-10-19/data-path/README.md).
`BenchmarkBondRecordLink` uses verified H2/TLS, two entries to one hub, ordered
1 MiB echo, eight-record windows, and the same logical-record delay for both
implementations. The fault model drops one successful upload acknowledgement
per sequence divisible by 17. This is **not packet loss**, bandwidth shaping, or
an Internet trial. The local delay adapter's allocations/CPU are included.
Legacy response delay is applied after the hub releases its mutex; otherwise the
model would introduce artificial serialization.

`Benchmark(NSS)?BondedDataPath` uses real SOCKS, two HTTPS relays, a separate HTTPS
exit and TCP echo, with 137-byte and 32 KiB application writes. Setup is excluded;
initial channel establishment and pool adaptation during measurement are included.
The p95 is the nearest-rank percentile of measured echo durations, not independent
request latency. Twenty exchanges per repetition still make a small sample.

```sh
go test ./internal/bond -run '^$' -bench BenchmarkBondRecordLink \
  -benchmem -benchtime=20x -count=3 -timeout=120s
go test -tags nss ./internal/tunnel -run '^$' \
  -bench 'Benchmark(NSS)?BondedDataPath' -benchmem -benchtime=500ms -count=3
# Capture each mode separately; keep pprof/binary outputs outside the source tree.
go test -tags nss ./internal/tunnel -run '^$' \
  -bench 'BenchmarkNSSBondedDataPath/lanes/write32768$' -benchtime=3s \
  -cpuprofile=/tmp/bond-lanes.cpu -memprofile=/tmp/bond-lanes.mem \
  -o /tmp/bond-profile.test
go tool pprof -top /tmp/bond-profile.test /tmp/bond-lanes.cpu
go tool pprof -top -alloc_space /tmp/bond-profile.test /tmp/bond-lanes.mem
```

The pinned Mozilla runtime must be on the loader path for the NSS commands.
For a real RTT/loss test use isolated client, entry and exit machines/namespaces,
shape **both** directions of each route, and record `tc -s qdisc`, CPU, RSS,
throughput and p95 for identical workloads/versions. Packet-loss/retransmission,
independent bandwidth budgets and field results remain unmeasured here. Path
selection still uses pending requests and smoothed delivery duration, not a
measured available-bandwidth estimator. Native C profiling and sustained RSS tests
also remain follow-up validation; process high-water RSS in this harness is not
per-session native memory.

## Verification

Real SOCKS tests cover Go/NSS, H2 POST, WSS, all three XHTTP modes and existing
quic-go H3 with Go TLS. They discard an already delivered write's reply, blackhole
one entry mid-stream, verify varying bytes across 2 MiB, retain one destination
socket and check half-close. Existing legacy lost-open/lost-ACK tests remain.
Additional tests cover capability negotiation across mixed relays, short-write
timer flush, receive-slot reuse, malformed lengths/session bindings, lane admission,
bounded backpressure, cancellation, and terminal protocol/TLS errors. Go/NSS race,
vet and external SDK checks retain the stage-two TLS/CA/SNI/pin coverage.
