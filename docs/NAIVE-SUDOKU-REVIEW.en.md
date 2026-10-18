[Русский](NAIVE-SUDOKU-REVIEW.md) | **English**

# NaiveProxy and Sudoku: limitations and transferable design

## Scope and pinned sources

Reviewed source snapshots:

- [NaiveProxy](https://github.com/klzgrad/naiveproxy/tree/0539676ac91d9607caa00869b709e66643b91ac5),
  particularly `USAGE.txt`, README and `src/net/tools/naive/naive_padding_socket.cc`.
- [Sudoku](https://github.com/SUDOKU-ASCII/sudoku/tree/a3a4c8a081221f2a352f2c36deaf8137900718b1),
  particularly `internal/tunnel/mux_dialer.go`, `mux_session.go`, `mux_stream.go`
  and the README. This is the network proxy project SUDOKU-ASCII/sudoku.

This is a source review and local regression work. No deployed NaiveProxy/Sudoku
vulnerability or successful TSPU classification was demonstrated. Architectural
tradeoffs must not be presented as exploitable security bugs.

## NaiveProxy audit and FoxTunnel status

| Limitation or tradeoff | FoxTunnel response | Remaining boundary |
| --- | --- | --- |
| An unavailable configured entry can interrupt service. | Explicit trusted alternatives, bounded setup failover and cooldown are now implemented. | Shared deployment risk, not a unique Naive flaw; all entries can still be blocked. |
| HTTP/2 over TCP shares loss recovery across streams. | New streams can be distributed across independent origins. | Each connection retains TCP head-of-line blocking. Naive already offers QUIC; FoxTunnel does not yet. |
| Extra tunnel connections can improve bad-path behavior but change observable patterns. | Explicit failover/round-robin/least-active selection; no automatic packet striping. | Naive already has concurrency controls and warns about detectability. More parallelism is not proof of concealment. |
| Long-lived-connection retirement trades recovery against application continuity. | FoxTunnel setup deadlines do not impose stream lifetime limits. | A broken established stream still fails; no transparent migration. |
| Initial padding leaves later length/timing information. | Existing optional bounded prefix padding remains. | Neither copying the first-eight-record idea nor changing its bytes proves resistance to traffic analysis. |
| Browser-derived behavior needs continual maintenance. | NSS is isolated behind an explicit backend and fingerprint comparison tooling exists. | Go H2 plus NSS is not Firefox Necko/Neqo. Naive's Chromium integration is more mature. |
| Server behavior and hosting can be observed or blocked. | Public website handler and authenticated admission limits already exist. | FoxTunnel's static cover is not equivalent to a mature browser/server deployment and does not prevent IP blocking. |

During the audit we also fixed a FoxTunnel-specific gap: the Go TLS backend now
requires h2 ALPN **before** sending proxy authentication, matching the NSS policy.
It cannot silently use an HTTP/1 tunnel. Certificate/ALPN/protocol failures remain
terminal even with multiple configured origins.

There is no basis for claiming that FoxTunnel has eliminated all NaiveProxy
weaknesses or is currently faster, less detectable, or generally more capable.
The new work improves explicitly testable failure handling and distribution.

## What Sudoku contributes

Sudoku's mux implementation provides useful examples of reusable sessions,
serialized session creation, directional close handling, bounded unread queues
and batched small writes. Its current source caps unread data per logical stream
and resets an overflowing stream instead of blocking the shared reader. These
are concrete lifecycle/resource ideas worth testing in any future custom mux.

FoxTunnel already delegates multiplexing to H2. Adding another Sudoku-style mux
inside H2 would duplicate framing and flow control. We retain existing H2 reuse
and half-close handling, and independently implement bounded endpoint selection
and recovery. No Sudoku source code or wire format was copied.

Sudoku encoding/low entropy alone is not browser behavior or encryption. Inside
TLS it also does not control the ciphertext's visible entropy. A separate raw
transport would need independent security and classifier evaluation. We therefore
do not add ASCII encoding, nested disguises or arbitrary padding to this HTTPS
baseline on the assumption that they improve concealment.

Sudoku's GPL terms and additional naming condition must be evaluated before any
future source reuse; architectural learning here does not import its code.

## Next experiments, not implemented features

1. Compare concurrent small requests while a bulk stream is stalled: memory,
   tail latency and cancellation for both TLS backends. H2 per-stream flow
   control must be evaluated separately from underlying TCP loss recovery.
2. Measure cold/warm setup p50/p95 and CPU with one versus several origins,
   including a blackholed endpoint. Least-active counts are not bandwidth weights.
3. Evaluate bounded warm connection pools only after observing handshake cost
   and traffic patterns; do not create an unlimited reconnect/prewarm storm.
4. Integrate a separate Neqo/H3 experiment and compare against Naive QUIC on
   the same route, including blocked UDP. Keep a verified H2 fallback.
5. Version Firefox reference captures, test TLS and H2 differences, then conduct
   repeatable observations on affected Russian networks. No current local test
   predicts TSPU resistance.

See [endpoint configuration](ENDPOINTS.en.md), [transport strategy](TRANSPORT-STRATEGY.en.md)
and [measurement methodology](PERFORMANCE.en.md).
