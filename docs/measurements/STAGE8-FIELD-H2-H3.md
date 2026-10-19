# Stage 8 of 11 — FoxTunnel H2/H3 real-path field measurements

**Status:** test harness implemented; no independent internet/VDS measurement
or Russian mobile-carrier measurement is available in this repository yet.
Passing local CI does not turn this into a field measurement.

## Topology and prerequisites

Run the **stage-7 Mozilla Linux/amd64 binary** on a measurement host and a
**separate controlled FoxTunnel server** (with trusted TLS certificate, TCP/H2
and UDP/H3 on the same origin). The exit must be able to reach a **controlled
TCP echo service**, preferably on a separate machine with a restrictive ACL.
Keep the echo service and server credentials off the public internet.

Use the *same* FoxTunnel server, TLS identity, credentials, echo target,
network path and payload for both transports. For H3, use Neqo with
`--h3-fallback none` by default; otherwise an H3-labelled SOCKS client
could silently exercise NSS/H2 when UDP is blocked.

The script starts two independent clients locally:
- NSS with `h2-post` (loopback SOCKS on port 11080 by default)
- Neqo with `h3-post` (loopback SOCKS on port 11081 by default)

It then uses the existing verified-echo workload in
`scripts/compare_transports.py`, rotating run order and measuring warmup,
CONNECT p50/p95, per-flow throughput, and success/error categories.
It cross-checks the **actual transport-selection counters** exposed by
`--engine-status-interval 1s`; without the expected carrier selection a
run fails even if the echo would otherwise succeed. Client processes are
terminated on exit, including measurement failure. Authentication secrets
are never passed on the command line.

## Run against independent remote infrastructure

Build/extract the pinned Mozilla bundle, then set environment variables
privately. Do **not** pass these on the command line or commit them.

~~~sh
export FOXTUNNEL_USER='<private user>'
export FOXTUNNEL_PASSWORD='<private password>'
umask 077

python3 scripts/field_h2_h3.py \
  --binary ./foxtunnel \
  --server https://your-owned-server.example \
  --ca-cert /private/trusted-ca.pem \
  --target 198.51.100.10:9000 \
  --rounds 20 --warmup 2 --parallel 4 --bytes 4194304 \
  --out stage8-healthy-private.json
~~~

The address above is **documentation-only**. Substitute your controlled
echo host; it must be reachable from the FoxTunnel server exit. Omit
`--ca-cert` if the normal system trust store validates the certificate.
Do not enable FoxTunnel's `--allow-private` on a public proxy to reach an
unprotected loopback echo service.

For a controlled loss scenario: **first** restrict UDP to the FoxTunnel
server for the measurement host using a separately managed, reversible lab
firewall rule; leave TCP/H2 available. Do not block UDP systemwide or alter
production/CI runner firewall rules. Then measure the explicit Neqo→NSS
fallback:

~~~sh
python3 scripts/field_h2_h3.py \
  --binary ./foxtunnel --server https://your-owned-server.example \
  --target 198.51.100.10:9000 \
  --h3-fallback h2 --expect-h3-route h2 \
  --scenario udp-blocked --out stage8-blocked-private.json
~~~

Restore UDP before a third `--scenario recovered` run, using default H3
expectation. **Important:** every invocation starts fresh clients. This
shows fresh-route H3 availability after recovery, NOT automatic recovery of
the **same long-lived client**, which requires a separate experiment using
`NotifyNetworkChange` or the 30-second reprobe. The script does not
automatically introduce network loss or claim that it did.

## Evidence and privacy

Output is exclusive-create **mode 0600** and intentionally omits server and
echo target addresses, user/password, CA paths, SNI/pins and raw exception
messages. Logs from the spawned clients are held in a temporary private
directory and removed; counters are included in the report.

The report contains binary SHA-256, OS/Python, declared scenario, workload,
full payload verification outcomes, route-selection counters, speed and
connection-time samples. It **cannot verify** independently that the server
really resides on a different network: record private sidecar notes on the
location/operator, time-of-day, MTU, measured packet loss and server CPU/RSS.
Do not commit raw packet captures or connection links.

**Pass criteria:** both clients each meet the selected success threshold
(default 95%) AND expected H2/H3 selection is observed. Passing does not
mean equivalent browser fingerprints, resistance to TSPU/DPI, or VPN
production readiness. A field claim needs the saved report **and** evidence
of two independent endpoints and the route. The run should be repeated on
each intended provider and route, especially when testing mobile networks.

## CI scope

GitHub Actions builds and exercises genuine local H2/H3 transport using its
separate integration tests, but hosted-runner loopback is **not a remote
operator measurement**. Stage 8 does not include credentials or deploy a
public measurement server. Its offline harness unit tests verify parsing,
route expectations and privacy; actual field JSON files belong in private
operator storage unless independently reviewed and redacted.
