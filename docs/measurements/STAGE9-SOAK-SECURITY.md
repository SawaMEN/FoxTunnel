# FoxTunnel stage 9 / 11: NSS/Neqo soak, recovery and TLS safety

The job uses **real TCP/H2, UDP/H3, NSS and Rust Neqo**, on a single
self-hosted process topology inside a GitHub Actions Linux runner. It
exercises both client processes concurrently against an ephemeral TLS
server and a controlled echo service. It does **not** access external
VDS/mobile networks and does not test DPI or Firefox fidelity.

## Bounded acceptance

- 75 seconds of continuous mixed H2/H3 echo with 3 parallel flows per
  carrier (configurable) and full byte-integrity checks; at least 98%
  success while the healthy server is reachable.
- Snapshot RSS includes the whole native client process, including Go,
  NSS, Neqo/Rust and loaded shared libraries. Each client must stay
  below 512 MiB peak, grow by no more than 192 MiB between warm
  baseline and end, and hold at most 512 open file descriptors.
  These are **budget guards, not a native leak detector**. Counters cannot
  pinpoint allocations inside NSS or Rust.
- Temporarily terminate the TLS/QUIC server, check both existing clients
  observe failures, then relaunch the same verified server and require two
  consecutive successful fresh echo requests per carrier, with up to 100
  seconds for old QUIC connections to retire. This explicitly does not
  replay failed streams or claim seamless migration.
- Start new clients with an intentionally invalid verified TLS DNS name.
  Both must reject application traffic; Neqo with H2 fallback enabled
  must not select H2 on a TLS identity error.
- Save a schema-versioned **private (0600)** JSON report with summary
  counters and memory budgets only. Never publish passwords, certificate
  private keys, server logs, raw exception strings or target addresses.

The workflow is triggered by modifications to stage-9 harness files;
existing repository CI also runs Go race and NSS/Neqo interop tests.
No production firewall manipulation, no deliberately leaking live
credentials, and no public listeners are used. Server `--allow-private`
is permitted only inside this isolated loopback laboratory.

## Manual repeatability

Build and extract the Mozilla Linux amd64 bundle, create a temporary
localhost certificate, and set `FOXTUNNEL_USER` and
`FOXTUNNEL_PASSWORD` privately in the environment. Then run:

~~~sh
umask 077
python3 scripts/soak_h2_h3.py \
  --binary ./foxtunnel --cert /private/lab-cert.pem \
  --key /private/lab-key.pem \
  --seconds 75 --parallel 3 --recovery-seconds 100 \
  --out /private/stage9-results.json
~~~

Ensure loopback ports 18443 (TCP and UDP), 19000 (echo), 11080, 11081,
12080 and 12081 are free on the isolated measurement machine. Do not
run a lab server with `--allow-private` on a public interface.

Passing this stage supports only bounded local workload and the observed
recovery behavior. Before production, test 24–72h sustained load,
external network interruption, traffic burst/cancellation, process
limits and RSS trends, certificate revocation/rotation, crash recovery
and independent security audit.
