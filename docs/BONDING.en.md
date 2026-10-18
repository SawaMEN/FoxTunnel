# Experimental multi-node stream bonding

For one-address links with coordinator-issued topology and capacity weights,
see [main-node cluster management](CLUSTER.en.md). Explicit-node setup remains supported.

[Русский](BONDING.md) | **English**

`--bond` carries blocks of a single TCP stream through two to eight trusted
HTTPS entry nodes to one common HTTPS exit. The exit retains one destination
socket, reorders blocks and suppresses retransmitted duplicates. Ordinary
`--balance` modes continue to distribute whole streams independently.

This is an experimental HTTP/2/TLS carrier, not MPTCP or Multipath QUIC. It does
not establish Internet speed, Firefox equivalence or Russian TSPU resistance.

## Deployment

Configure the same `FOXTUNNEL_USER` / `FOXTUNNEL_PASSWORD` on all processes and
valid certificates on each server. All nodes are trusted: TLS terminates at each
hop. Application HTTPS remains end-to-end if the application uses it. Synchronize
client/exit clocks: new tokens expire after 30 seconds, with up to five seconds
of future skew allowed. Tokens include creation time and 192 random bits.

Exit:

```sh
./foxtunnel server --listen :443 --cert exit.crt --key exit.key \
  --web-root /srv/public-site --bond-hub
```

Each entry, using its own certificate and the same exit:

```sh
./foxtunnel server --listen :443 --cert node-a.crt --key node-a.key \
  --web-root /srv/public-site --bond-upstream https://exit.example
```

Add `--bond-ca-cert exit-ca.pem` on entries for a private exit CA.
`--bond-hub` and `--bond-upstream` are mutually exclusive. TLS certificate and
h2 ALPN validation are required; redirects are not followed.

Client:

```sh
./foxtunnel client --server https://node-a.example \
  --fallback-server https://node-b.example --bond \
  --connect-timeout 15s --fallback-attempt-timeout 5s --lang en
```

At least two entries must be configured, but a session can continue through one
surviving entry. `--ca-cert` applies to entry certificates. Optional NSS requires
`-tags nss` and `--tls-backend nss`; entry-to-exit TLS currently uses Go.
`--padding` is explicitly incompatible. `--balance` only controls ordinary CONNECT;
bonding uses its own adaptive scheduler.

## Scheduling, reliability and bounds

Selection uses outstanding request count and an EWMA of complete request duration
(7/8 old + 1/8 new). Untested paths receive demand-driven exploration. Transient
failures prefer other paths for five seconds; no background probing. This measures
HTTP exchange time including exit waits, not pure RTT or available bandwidth.

Four upload/fetch slots are used at low delay; automatic mode can expand to eight,
including small SOCKS
reads. Blocks carry up to 32 KiB and retain sequence numbers on retry. The exit
acknowledges upload only after writing to the same destination socket. Delivered
sequence numbers are not written twice; conflicting pending duplicates fail.
Downloads use ordered delivery and cumulative consumed-block acknowledgements.
Empty long polls return 204 within the attempt budget.

408/429/503/504 and transient network failures can retry these session-scoped
operations. Ordinary CONNECT HTTP errors remain terminal. Certificate, TLS and
protocol errors do not weaken verification. A random exit-instance identity
binds subsequent requests to one process; differently configured exits reject
bound requests before destination work. A lost initial open response can leave
an unused socket until cleanup, but application data is not split across exits.

The exit retains at most eight upload blocks and eight download-data blocks plus
a possible EOF marker; the client retains four to eight per direction. HTTP/TLS/socket
buffers are additional. Default exit capacity is 256 active sessions.
`--max-tunnels` also bounds concurrent authenticated CONNECT/RPC handlers.
Closed sessions release payload but retain tombstones for at least two minutes after the last request, with lazy
on-demand cleanup;
at most 4096 records are retained. Two minutes without requests closes the socket,
even without further arrivals. Destination setup has a ten-second limit.

Client setup uses `--connect-timeout`; each attempt uses
`--fallback-attempt-timeout` (minimum 100ms here). Each operation tries each entry
at most once per sweep, with at most three sweeps and cancellation-aware
25ms/50ms pauses between failed sweeps. The same token, hub identity, sequence
and payload are retained: a lost response after delivery does not redial the
destination or write that block twice. Only the transient errors/statuses listed
above permit another sweep; authentication, certificate/TLS, protocol, wrong-hub
and closed-session errors stop immediately. All attempts remain subject to the
parent setup/stream context and the configured per-attempt timeout. The upper
bound is three times the number of entries, not unlimited retries. If every sweep
fails or the common exit is lost, the stream terminates.
There is no durable state replication or exit-socket migration. Upload half-close
waits for earlier acknowledgements. Entry changes cannot repair a failed origin
website or an exit-IP restriction; encrypted application HTTP is not inspected
or replayed. Shared bottlenecks and framing/TLS overhead limit throughput.

## Validation and future work

Real SOCKS5, two HTTPS relays, a separate HTTPS exit and a TCP service test lost
open replies, lost delivered-block ACKs, a blackholed entry midstream, ordering,
absence of duplicates and half-close with both Go TLS and NSS. Separate tests
cover concurrent small writes, bounded bodies/windows, expired/closed tokens,
wrong exit identity and close during dial.

```sh
go test -race ./... -count=1 -timeout=60s
go test -race -tags nss ./... -count=1 -timeout=120s
go test ./internal/tunnel -run '^$' \
  -bench 'Benchmark(BondedLoopback|TunnelRoundTrip)' -benchmem -benchtime=500ms -count=3
```

Independent constrained routes, aggregate bandwidth, p95, recovery time, CPU,
memory, small messages and idle overhead remain to be measured. Bandwidth-aware
scheduling, suitable congestion control, economical streaming framing and Neqo/H3
are future work. Recheck traffic fingerprints and real Russian networks.

References: [MPTCP RFC 8684](https://www.rfc-editor.org/rfc/rfc8684.html) and
[Multipath QUIC tracker](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/).
The observed tracker showed draft-21; this does not establish Neqo support or
production readiness of this independent prototype.

### Buffer reuse

The format and window sizes are unchanged. Client/exit buffers are reused with
ACK-aware ownership; original/rewound HTTP readers finish before upload storage
is overwritten. Relay buffers use a bounded, cleared 32-by-32-KiB cache.
See [profile, before/after observations and limits](PERFORMANCE.en.md#bonding-buffer-optimization).

### Automatic pipeline and attempt budget

`--bond-pipeline auto` is the default. A fastest measured usable exchange duration
of at least 25ms permits four-to-eight expansion. Empty 204 polls do not inflate
this metric; it includes server/initial-handshake time and is not pure RTT or
bandwidth. Fixed 4/8 modes are available. The server window remains eight and
v1 framing is unchanged. Upload slots already allocated are not revoked within
a stream; receive prefetch can reduce future work. Buffers allocate on demand.

A measured usable alternative can shorten session-operation attempts to the
minimum of the configured cap and max(250ms, four times its measured duration).
Unknown/cooling alternatives do not shorten attempts. Open retains its full
setup budget. Sequence numbers and verification remain unchanged, no background
probing, and loss of all paths still terminates the stream.

### Recovery regression check

A deterministic shared-hub test drops both entries' first responses after each
open/write/read/FIN/close has already reached the exit. It checks one destination
dial, unchanged bytes and retained session identity. Additional tests bound the
attempt count and verify cancellation and terminal TLS/authentication failures.
This covers a temporary failure of all paths; it does not replicate exit state
or guarantee recovery from arbitrary-duration outages.
