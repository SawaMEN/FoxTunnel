# TCP core: lifecycle and failure contract

[Implementation plan](IMPLEMENTATION-PLAN.md) · [Wire draft 0](reference/WIRE-DRAFT-0.md)

The baseline carriers are H2 CONNECT, H2 POST and WebSocket carrying inner H2.
NSS is an alternate verified TLS backend. H3/Neqo have additional experimental
network-recovery requirements; XHTTP and multi-node/bond remain experimental.
The regression matrix does not constitute a production-performance guarantee.

## Stream semantics

The dial context and ConnectTimeout bound setup. After a successful dial, the
returned connection belongs to its caller; cancelling the completed setup
context does not stop the stream. Close cancels the request, unblocks pending
reads/writes and releases the endpoint reservation. SOCKS ServeContext also
joins its active and incomplete connection handlers on shutdown.

CloseWrite ends the client's upload, half-closes the destination write side
and preserves the reply path. Read EOF means clean response-body completion.
The current net/http server ends the association when the destination read
side ends; independent destination-to-client FIN while continuing upload is
not a supported half-close guarantee. It would need a separate implementation
or negotiated framing change. Always close an owned connection after use.

A target reset/read failure after HTTP 200 resets the HTTP stream; it must not
be returned as a successful END_STREAM. The direct Go connection preserves the
original transport/decoder error when shutting down its local pipes. On the
SOCKS side, a failed download resets the local TCP connection where SetLinger
is available, rather than signalling normal EOF. A SOCKS stream cannot convey
the exact remote Go error after CONNECT.

## Backpressure and deadlines

The direct-connection adapter uses synchronous net.Pipe/io.Pipe and one bounded
copy chunk per pump. An upload cannot accumulate an unbounded application queue
when the carrier stops reading. Transport, TLS and kernel buffers have their own
separate limits; the copy-chunk test is not a total-process memory bound.

Read/write deadlines apply to the application-facing connection. Resetting a
deadline permits further I/O; a timeout does not replay accepted bytes or
recreate a stream. A write count reports accepted bytes, not delivery to the
destination. Closing a stream must unblock a writer stalled by transport flow
control and release its endpoint reservation.

## Setup failures and replay

Only transient setup failures before any HTTP response, with no application
bytes submitted, may try an explicitly configured fallback. Certificate,
ALPN, version/capability/padding refusal and any HTTP response are terminal.
A response plus a transport error is still a response and must not trigger
fallback. An established upload is never replayed after a partial response,
RST or ambiguous write failure.

Rejected setup teardown cancels its request context and closes upload pipes
before closing the response body. Some duplex transports wait for the upload
worker in Body.Close; reversing that order can deadlock a refused connection.

## Evidence

The `TCP core stability` workflow repeats the following under the Go race
detector for Go and NSS builds:

- Twelve reset-after-prefix cases per backend: CONNECT/POST/WSS, plain/padded,
  direct DialContext and local SOCKS.
- Exhausted-upload-credit simulation, bounded copy acceptance, read/write
  deadline reset, cancellation and reservation release.
- Context-dependent Body.Close for HTTP refusal and response-plus-error,
  asserting exactly one attempt.
- Public ServeSOCKS supervision forwards TCP reset signalling through its
  owned connection wrapper, verified with an actual target RST.
- Actual TLS/H2 partial upload/response followed by RST, asserting no backup
  request and no successful EOF.
- Existing half-close, setup-timeout, cancelled target, eight-parallel-stream,
  native carrier and fallback tests, repeated three times.

These are bounded local loopback/software checks. Extended resource soaks,
benchmarks and noisy-network behavior remain in the later plan stages.
