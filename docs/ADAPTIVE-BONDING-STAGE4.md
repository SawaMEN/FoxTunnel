# Stage 4 — independent WAN measurement and release gates

[Node guide](NODES.md) · [Stage 3 UDP flow sharding](ADAPTIVE-BONDING-STAGE3.md) ·
[Existing benchmark criteria](NODE-BENCHMARK-AND-MERGE.md)

## Stage-4 status

The TCP and UDP field probe, bounded echo targets and three-day acceptance
validator are implemented. CI can verify **loopback correctness**, not the
speed, loss or RTT of VDS networks we do not control. Do not claim field
improvements or move experimental flags into defaults based on CI.

The probe does not provision hosts or access remote VDS. Reports only carry
proxy labels, anonymized measurements and a user-attested environment marker.
`--confirm-independent-vds` is an operator declaration, **not verification**.

## Setup: independent hosts

Use at least three distinct machines (a measurement client and two
independent trusted VDS ingress nodes), with a controlled TCP/UDP echo
destination accessible from both server exits. The same physical host running
two Docker instances is **not** an independent VDS experiment. For TCP
Bonding, configure the shared authenticated hub and ingress/relay topology
described in [NODES.md](NODES.md). UDP per-destination sharding is a
different mode, and no `--bond --udp-multi-node` combination is supported.

Protect echo listeners with cloud firewall/allowlisted source IPs and short
test windows. The helpers have **no authentication** and must never be
published openly to the Internet. To listen on a non-loopback numeric IP,
pass `--allow-public` *only* in a restricted lab:

```sh
python3 scripts/echo_server.py --host 127.0.0.1 --port 9000
python3 scripts/udp_echo_server.py --host 127.0.0.1 --port 9001
```

For independent VDS test hosts, bind to their firewall-restricted private
interface with `--allow-public`. Do not expose an open echo service to
arbitrary clients.

## Launch separate client variants

Use different local SOCKS5 listening ports. For each ingress arrangement
use the same TLS version, verified certificates, server and echo target.
Never put credentials in CLI flags or published output. For example, a
TCP Bond client on the test workstation:

```sh
# Stage-1 adaptive experiment vs preexisting Bond baseline
foxtunnel client --server https://hub.example \
  --fallback-server https://ingress.example \
  --bond --bond-pipeline auto --listen 127.0.0.1:11080

foxtunnel client --server https://hub.example \
  --fallback-server https://ingress.example \
  --bond --bond-pipeline auto --bond-adaptive --bond-autotune \
  --bond-traffic auto --listen 127.0.0.1:11081
```

Both trusted ingress paths **must share the same authenticated hub**, or
the stream opening will correctly fail. These example hostnames do not
represent provisioned servers. For UDP, run separate `--enable-udp
--udp-stream` and `--enable-udp --udp-stream --udp-multi-node` clients
(with 2+ explicit fallback origins for multi-node mode), on different
local ports; UDP flow sharding does not rely on Bond.

## Measure TCP small exchanges and bulk

Run both variants in alternating order to reduce thermal/time bias.
Use a *controlled* echo server. Save one report per run; files will not be
overwritten.

```sh
python3 scripts/bond_stage4_field.py \
  --mode tcp --environment wan --confirm-independent-vds \
  --scenario tcp-small --proxy legacy=127.0.0.1:11080 \
  --proxy adaptive=127.0.0.1:11081 \
  --target echo.private.example:9000 \
  --bytes 1024 --rounds 30 --parallel 2 \
  --out results/tcp-small-day1.json

python3 scripts/bond_stage4_field.py \
  --mode tcp --environment wan --confirm-independent-vds \
  --scenario tcp-bulk --proxy legacy=127.0.0.1:11080 \
  --proxy adaptive=127.0.0.1:11081 \
  --target echo.private.example:9000 \
  --bytes 33554432 --rounds 30 --parallel 2 --timeout 30 \
  --out results/tcp-bulk-day1.json
```

TCP p50/p95/p99 are **application-level completion times** (SOCKS
CONNECT plus verified echo transfer), not network ICMP ping. Goodput Mbps
is payload bytes / elapsed transfer time; it is not link capacity.
A shared hub can bottleneck multi-ingress traffic.

## Measure UDP response time, loss and jitter

Use controlled UDP echo targets, preferably at least two distinct ports
to allow both UDP exits to be exercised. Never compare UDP latency of
different destination hosts as though it were the same network path.

```sh
python3 scripts/bond_stage4_field.py \
  --mode udp --environment wan --confirm-independent-vds \
  --scenario udp-multi --proxy legacy=127.0.0.1:11082 \
  --proxy adaptive=127.0.0.1:11083 \
  --target echo.private.example:9001 \
  --target echo.private.example:9002 \
  --rounds 30 --parallel 2 --timeout 3 \
  --out results/udp-day1.json
```

UDP RTT is *client-observed echo request/response time*, including
SOCKS5-to-HTTPS encapsulation, not underlying physical path RTT. Loss
includes timeouts, rejected associations and invalid responses, not
pure network packet-loss estimates. Jitter is average absolute change
between consecutive successful observed RTT samples; report this
approximation separately from RFC 3550 interarrival jitter.

## Three-day field acceptance, no automatic release

Repeat matched scenarios for **at least three different UTC days**,
with five or more completed samples for every proxy/day, and compare
reports separately per scenario. Example:

```sh
python3 scripts/bond_stage4_gate.py \
  --baseline results/tcp-small-day1.json \
  --baseline results/tcp-small-day2.json \
  --baseline results/tcp-small-day3.json \
  --candidate results/tcp-small-day1.json \
  --candidate results/tcp-small-day2.json \
  --candidate results/tcp-small-day3.json \
  --baseline-label legacy --candidate-label adaptive \
  --out results/tcp-small-gate.json
```

The shared report files are allowed because each contains samples for
both variant labels; the gate filters each label independently. It
requires a consistent scenario and transfer size, success >=99%,
zero integrity mismatches, and rejects >10% p95 completion/UDP RTT
regression, >10% TCP bulk median goodput regression or UDP loss rising
by more than one percentage point. All estimates are descriptive:
minimum sizes are *not* a formal confidence interval; inspect runs
and repeated measurements manually.

**Fault injection:** Shut down one trusted ingress at a planned
boundary, capture time to recovery and whether already established
TCP flows survive. For UDP, validate that a lost exit **terminates**
the association (no hidden NAT/source swap) and that an application can
make a *new* association afterward. Do not inject loss on production
interfaces. Repeat loss/delay tests using `tc netem` on isolated lab
interfaces only; capture real loss/jitter separately.

**Resource gate:** record per-client CPU, RSS, file descriptors and
connections over a 30-minute soak while sending concurrent bulk and
small exchanges. Compare against the single-node baseline and check
the memory ceiling before merge. The existing stage-9 native soak tool
can capture RSS/FD on Linux, but its loopback run is not a VDS result.

## Review policy

- No secrets, endpoint hostnames or raw exception data in checked-in reports.
- Stage-4 CI only verifies probe correctness, redaction, safe parser
  behavior, UDP correctness on local sockets and compatibility tests.
- Require a manually reviewed VDS topology, WAN report triplicate,
  packet-loss/jitter methodology, CPU/RSS budget and TLS trust review.
- PRs #24 → #25 → #26 → stage-4 are stacked and **not merged** by default.
  Review the dependency chain and do not enable feature flags by default
  until those independent checks pass.
