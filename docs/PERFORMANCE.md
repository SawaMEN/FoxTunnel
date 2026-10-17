# Performance and network validation

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
connection reuse and timing. Current fingerprint tooling captures only TLS
ClientHello; no current Firefox reference trace is shipped. A static website
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
