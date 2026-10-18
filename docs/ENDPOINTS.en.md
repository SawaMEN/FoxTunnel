[Русский](ENDPOINTS.md) | **English**

# Trusted endpoints and new-stream scheduling

Configure up to eight HTTPS proxy origins owned or trusted by the operator:

```sh
./foxtunnel client \
  --server https://edge-a.example \
  --fallback-server https://edge-b.example \
  --fallback-server https://edge-c.example \
  --balance least-active \
  --connect-timeout 15s \
  --fallback-attempt-timeout 5s
```

All configured origins receive the same proxy credentials, only after verified
TLS 1.3 and h2 ALPN. Configure certificates and credentials on each server.
Do not add arbitrary public proxies. URL userinfo, non-root paths, queries,
fragments, duplicates and cleartext origins are rejected. `--ca-cert`, the
selected TLS backend and padding policy apply to every origin. No automatic
endpoint discovery or redirect following is performed.

## Selection and recovery

| Mode | New-stream behavior |
| --- | --- |
| `failover` (default) | Start with the last successful origin; use another on transient setup failure. |
| `round-robin` | Rotate the starting origin; useful for similarly sized servers. |
| `least-active` | Prefer the origin with the fewest locally outstanding setups and open streams; rotate ties. |

Counts are reserved atomically with selection and returned once during teardown.
They describe this client, not global server CPU, bandwidth or other users.
HTTP/2 already multiplexes concurrent streams; Go goroutines perform concurrent
I/O and the Go runtime schedules runnable work across available CPUs. This
change adds independent origins, not a custom thread pool or packet striping.

A failed setup can try each origin at most once. One 15-second default budget
covers all attempts; each attempt has a five-second cap when multiple origins
are configured. Application bytes wait for a successful CONNECT and matching
padding negotiation. Setup timers stop on success and do not retire a healthy
long-lived SSH/download stream.

Transient network failures put an origin in a local cooldown: 1, 2, 4, 8, 16,
then at most 30 seconds. Ready origins are preferred. If every remaining origin
is cooling, attempts proceed immediately, so cooldown cannot prevent recovery.
There are no background probes or reconnect loops. Success clears its cooldown.
An origin becomes eligible again on later demand. This is bounded automatic
recovery, not a measured RTT/bandwidth optimizer.

Certificate, TLS protocol, ALPN, HTTP status and padding errors stop the current
setup. In particular, 401/403/503 are not silently retried elsewhere. Parent
cancellation stops all attempts. A certificate error is never treated as a reason
to weaken verification or switch to plaintext.

Once CONNECT succeeds, a stream stays on its selected origin. Its failure closes
that stream; application bytes are never replayed or migrated. Other streams on
other origins can continue. A single large download does not combine server
bandwidth. Switching origins can change the destination-visible exit IP.
Multiple streams on one H2/TCP connection still share TCP loss recovery.

## Limits and validation

More connections and endpoints can change observable traffic patterns. Neither
balancing nor endpoint rotation proves resistance to classification or IP blocks.
If all configured servers are blocked, these modes cannot restore connectivity.
No HTTP/3, DNSTT, split HTTP transport or Sudoku wire compatibility is added.

Regression tests cover real certificate-verified H2 connections using Go TLS
and NSS: distribution, selection after release, teardown, unavailable/stalled
origins, shared timeout budgets, certificate/HTTP/padding failures, HTTP/1-only
peers before authentication, and absence of established-stream replay. Concurrent
scheduler reservations and cooldown recovery are separately checked under the
race detector. Real-route throughput and Russian TSPU observations remain needed.

## Experimental stream bonding

The separate opt-in `--bond` mode carries blocks of one stream through multiple
entries to one common exit. Ordinary whole-stream scheduling remains available.
See [deployment, acknowledgements, limits and tests](BONDING.en.md).
No speed advantage or TSPU resistance is established.
