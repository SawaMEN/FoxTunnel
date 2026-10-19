# Performance and network validation

[Русский](PERFORMANCE.md) · **English** · [Research](README.en.md) · [Raw measurements](../measurements/README.en.md)

> **Scope:** Benchmark methodology and recorded experiments; localhost metrics are not field-network performance.

## What this milestone changes

- An operator-owned static website replaces the fixed product-branded page.
- TLS session tickets may resume subsequent connections using a bounded memory
  cache; the first handshake and the long-lived data path are not accelerated by
  this cache. Resumption changes ClientHello and needs separate reference traces.
- Dual-stack destination dialing falls back after 250 ms instead of waiting for
  a broken first family to consume the complete setup timeout. Address filtering
  happens before dialing; DNS is not repeated by a racing dialer.
- CONNECT setup times out independently of stream lifetime. Cancellation closes
  destination sockets even when the destination is silent. Normal upload EOF
  still allows a final response.

These are implementation improvements, not a claim of Firefox parity,
undetectability, censorship resistance, or superiority to NaiveProxy.

## Reproduce local measurements

```sh
go test -race ./... -count=1 -timeout=60s
go vet ./...
go test ./internal/tunnel -run '^$' -bench BenchmarkTunnelRoundTrip -benchmem -benchtime=1s -count=3
```

The benchmark establishes SOCKS5 over certificate-verified HTTP/2/TLS 1.3 and
then reuses a stream to echo 64-byte and 1-MiB messages. MB/s counts the payload
once, although each iteration sends it in both directions. Setup time is
excluded; allocations include the benchmark's upload goroutine/channel. This
is a loopback test, so it does not predict Internet speed or DPI behavior.
Do not run comparison benchmarks concurrently.

## Required comparisons before deployment claims

Compare the same server, client OS, route, payload and traffic limits with
NaiveProxy and real Firefox. Record software versions and both cold and resumed
TLS sessions. Measure connection setup p50/p95, throughput, CPU, peak memory,
success rate, disconnect recovery and overhead. Repeat with IPv6 failure,
latency, loss, blocked UDP and multiple concurrent applications.

Capture TLS ClientHello and HTTP/2 SETTINGS, initial windows, frame ordering,
connection reuse and timing. `ft-fingerprint` captures only TLS ClientHello. `ft-webprofile` additionally observes initial H2 fields and TLS
record metadata. [Firefox 158 Linux reference measurements and known
differences](WEB-PROFILE.en.md) are shipped; matched workloads and external
packet captures remain future work. A static website
does not change these passive client fingerprints or prevent IP-based blocks.

Censorship tests need explicit observations on the affected operator networks,
including successes and failures over time. Local unit tests cannot establish
that Russian TSPU will not classify or block a tunnel.

## Local observation (Go 1.23.12, Linux amd64)

Three sequential benchmark repetitions on an AMD EPYC 9V74 shared runner:

| Revision | 64-byte roundtrip | 1-MiB echo payload rate |
| --- | --- | --- |
| Baseline `8e74056` | 54.7–61.7 microseconds | 349.5–356.1 MB/s |
| This milestone | 54.2–65.3 microseconds | 352.0–385.3 MB/s |

These ranges overlap and the sample is small. They do **not** establish a
steady-state speed improvement. The intended gains are faster family fallback,
TLS resumption on reconnects and resource release on aborts. Those behaviors
have separate regression tests. Internet throughput and TSPU behavior remain
unmeasured.

## NSS adapter observation (Go 1.26.9, Linux amd64, NSS 3.98)

A separate run in one tagged binary, with both backends measured sequentially,
three 500-ms repetitions per case on the same shared AMD EPYC runner:

| Backend | 64-byte roundtrip | 1-MiB echo payload rate |
| --- | --- | --- |
| Go TLS | 54.4–58.6 microseconds | 316.3–380.4 MB/s |
| NSS TLS + Go H2 | 95.7–98.2 microseconds | 301.9–336.5 MB/s |

The initial NSS adapter does not show a speed advantage here. Native/Go callback
crossings and a different H2 implementation add work, especially for small
messages. These loopback samples are diagnostic, not Internet predictions or
statistically established regressions. No packet-loss, real-route, Firefox,
NaiveProxy or TSPU comparison has been run.

```sh
go test -tags nss ./internal/tunnel -run '^$' \
  -bench 'Benchmark(NSS)?TunnelRoundTrip' -benchmem -benchtime=500ms -count=3
```

Validation for the adapter also passed with Go's race detector, vet, ordinary
and tagged builds, CGO-disabled baseline tests, strict native compiler warnings,
and AddressSanitizer. The AddressSanitizer run used `detect_leaks=0` because this
runner cannot enumerate `/proc` threads for LeakSanitizer; no memory-leak scan
result is claimed.

## Initial-v1 padding observation (Go 1.26.9, NSS 3.98)

Three 500-ms repetitions per case on the shared Linux runner:

| Backend / mode | 64-byte roundtrip | 1-MiB echo payload rate |
| --- | --- | --- |
| Go, plain | 53.9–59.8 microseconds | 293.9–339.8 MB/s |
| Go, padding enabled | 59.7–63.5 microseconds | 196.3–321.7 MB/s |
| NSS, plain | 118.9–144.2 microseconds | 257.2–297.8 MB/s |
| NSS, padding enabled | 95.0–115.7 microseconds | 252.9–303.7 MB/s |

The stream benchmarks predominantly exercise the raw phase. The wide ranges
and even reversed plain/padded rankings show runner variance; they do not
establish a steady-state penalty or advantage. Padding stays disabled by
default. No Internet or classifier result is inferred from these samples.

The separate `BenchmarkInitialPaddingEncoder` discards encoded output, measuring
only CPU, wire-byte overhead and warmed-pool allocations for a new prefix:

| Payload in one write | Encoder time | Mean extra bytes |
| --- | --- | --- |
| 64 bytes (one record) | 60.5–70.7 ns | 130.5–130.6 |
| 16 KiB (one record) | 333.9–367.0 ns | 130.5–130.6 |
| 128 KiB (eight records) | 2.78–2.93 microseconds | 1044 |

The encoder microbenchmark reported zero allocations per operation after the
buffer pool was warmed. It excludes decoder allocation, HTTP/2, TLS, sockets,
setup and real network costs. See [padding format and bounds](../architecture/PADDING.en.md).

## CI fuzz budget correction

The first padding CI run passed race tests but failed after its 10-second fuzz
budget with `context deadline exceeded`, without a saved failing input. A local
Go 1.26.0 run did not reproduce the failure. This is consistent with a fuzz
coordinator deadline race, but the log alone does not prove the root cause.

CI now uses the latest Go 1.26 patch and a 100,000-execution fuzz budget with an
independent 120-second process timeout. Failures remain fatal; there is no retry
or error suppression. The same counted command passed locally. A real parser
crash or hang must still fail the job. Longer time-based campaigns remain useful
outside the bounded CI smoke check.

## Bonding prototype: loopback observation

Go 1.26.9, Linux amd64, shared AMD EPYC 9V74; three sequential 500-ms repetitions
without concurrent checks. One-MiB echo counts payload once and excludes setup.
Bonding uses two actual HTTPS entries and a separate HTTPS exit; ordinary CONNECT
uses one HTTPS server.

| Mode | 1-MiB echo, MB/s | Total allocated bytes per exchange |
| --- | --- | --- |
| Ordinary CONNECT, Go TLS | 245.04–390.40 | 21.9–24.3 kB |
| Bonding, Go TLS | 135.75–190.18 | 9.91–10.16 MB |

Allocation counts include all participating goroutines and the in-process
servers. They are not resident memory or wire overhead. Per-block HTTP requests,
a second TLS hop and copying have substantial cost; this prototype is slower in
this test. Independent constrained-route gains remain unmeasured. Runner variance
is large; no Internet or superiority claim follows. CPU/allocation profiling and
more economical streaming framing are next, preserving ACKs and bounded windows.

[Bonding design and deployment](../architecture/BONDING.en.md).

## Bonding buffer optimization

A three-second profile of `becd076` identified RPC-body reads, `io.Copy`, request
payload copies, exit downloads and queued uploads as major allocation sites.
Syscalls dominate CPU, with encryption, copying, scheduling and GC also visible.

The v1 format, block sizes and windows are unchanged. Four upload/four receive
buffers per client stream and eight exit receive slots are reused only after
ownership permits it. HTTP bodies present immutable header/payload slices without
a second full copy. `GetBody` supports transport retries; finishing an attempt
joins reads and invalidates every reader before an upload slot can be reused.
Relay copy buffers use a bounded 32-by-32-KiB cache, cleared on return; known-empty
responses skip it. Live session buffers remain retained until teardown. Allocated
bytes per exchange are not peak RSS; the relay cache is at most 1 MiB, separate
from active-request and HTTP/TLS buffers.

Both revisions ran sequentially on the same Go 1.26.9/Linux amd64/AMD EPYC 9V74
runner: three one-second repetitions without concurrent checks. The old revision
used a separate checkout. One-MiB echo counts payload once:

| Bonding revision | MB/s | Total allocated bytes per exchange |
| --- | --- | --- |
| `becd076` | 143.90–149.54 | 9.97–10.11 MB |
| Buffer reuse | 173.56–225.63 | 2.77–2.84 MB |

Observed median throughput improved about 37% and allocated bytes fell about 72%.
This small shared-runner sample provides no statistical guarantee. Ordinary
CONNECT remained faster: 290.65–360.61 MB/s before and 296.69–348.22 MB/s after.
Internet gains, independent-link aggregation and Russian TSPU resistance are not
inferred. Per-block request/ACK budgets still limit a stream at high RTT; a more
economical streaming carrier and real-route measurements remain necessary.

Tests cover partial consumption across receive-slot reuse, composite-body read
boundaries, invalidating original/rewound transport readers before upload reuse,
and calls after Close. End-to-end data now varies across blocks, exposing reorder
or overwrite bugs that repeated contents could hide. Lost ACKs, a blackholed entry,
half-close and both TLS backends remain covered under the race detector.

## Pipeline with synthetic RPC delay

The same binary uses two HTTPS entries and a common exit. Each entry waits 40ms
before forwarding a request. This models HTTP processing delay, not packet RTT,
loss or bandwidth. One-MiB echo, three 500-ms repetitions, Go 1.26.9/AMD EPYC 9V74:

| Pipeline | MB/s |
| --- | --- |
| 4 | 2.80–2.82 |
| 8 | 5.04–5.41 |
| auto | 5.37–5.80 |

Automatic mode approaches eight-slot throughput in this model. Small samples do
not establish Internet performance or independent-link gains. Real loss, TCP
queues, bandwidth and TSPU are not modeled. Per-block RPC remains a limitation;
a persistent streaming carrier is separate work. Eight slots retain more memory.

```sh
go test ./internal/tunnel -run '^$' -bench BenchmarkBondedDelayedRPC \
  -benchmem -benchtime=500ms -count=3
```
