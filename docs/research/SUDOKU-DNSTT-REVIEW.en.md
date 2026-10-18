# Sudoku and dnstt: follow-up review

[Русский](SUDOKU-DNSTT-REVIEW.md) | **English**

Reviewed October 18, 2026: selected source paths and official descriptions,
without running external protocols or testing Russian networks. Full source
links are in the [Russian report](SUDOKU-DNSTT-REVIEW.md).

## Sudoku

Snapshot `a3a4c8a081221f2a352f2c36deaf8137900718b1`, October 18, 2026.
Inspected mux session, stream, chunk and copy paths. Useful ideas: bounded
per-stream unread data, isolated overflow, half-close, small-write batching
and buffer ownership until the actual write completes. Limits are 4 MiB per
stream and 256 KiB for batching. A blocked writer's owned buffer remains
accounted and cannot be recycled early.

FoxTunnel already applies bounded windows and ownership in bond. Another mux
inside H2 would duplicate flow control. Persistent lanes/coalescing remain
future work. Sudoku/ASCII encoding inside TLS would add overhead without its
outer byte distribution. Obfuscation is not authenticated encryption. Its
README identifies TCP and UDP-over-TCP limitations. No code/format was copied;
direct reuse would require license and additional naming-condition review.
Claims of invisibility do not establish TSPU resistance.

## dnstt

Inspected the author's `dnstt-20260501.zip`, **v1.20260501.0** per changelog,
the latest archive observed on the author's page. SHA-256:
`a7b21d3d787570d9127643e360e150d2da7b33aa8039d0546a04dcfe8ee1864f`.
This records downloaded bytes, not PGP verification. A complete Git head was
not obtained; unpackaged changes are outside this review.

Inspected client main/DNS/HTTP, Noise, packet queues, constants and changelog.
Turbo Tunnel separates session/reliability from carriers: application → smux →
Noise → KCP → DNS → DoH/DoT/UDP. Bounded queues and idle polling backoff trade
latency against overhead. The 2026 release fixes a sendto error leaving a
running process unable to send replies: process health is not delivery health.

DNS offers tight message budgets and polling-dependent downstream delivery.
Noise NK authenticates the server, not clients. KCP sits outside Noise,
exposing sequence/ACK metadata to the resolver while protecting application
content. DoH/DoT does not replace end-to-end tunnel protection. Plain DNS is
not covert. The archive's uTLS is not a complete Firefox network stack.

Keep session/carrier separation, bounded state and delivery-based health. A
DNS carrier remains future emergency transport requiring client authorization
and protected transport state. KCP is not added inside reliable H2. This
change implements no DNS carrier.

## Delivered decision

[Main-node cluster management](../architecture/CLUSTER.en.md) adds one-address links,
authenticated bounded topology/weights, expiry, demand refresh and exit-process
binding before destination work. The main node retains reassembly. Existing
sessions retain their paths; new sessions receive updated topology. This is
an independent bond extension, not integration of Sudoku/dnstt source code.
