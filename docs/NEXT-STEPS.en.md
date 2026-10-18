# Next steps for FoxTunnel

[Русский](NEXT-STEPS.md) | **English**

Assessment after main `bc257ef`, 18 October 2026. Seven native transports, NSS TLS,
coordinator links and bounded local failure tests exist. These are engineering
priorities, not censorship-resistance claims.

| Priority | Work | Acceptance |
|---|---|---|
| 1: XHTTP deployment | Shared path/Host, validation, setup/link/join | Three modes through a controlled HTTPS frontend; independent Host/SNI; NSS; TLS rejection before HTTP; custom-route cluster |
| 2: efficiency | Bounded packet-up coalescing/pipeline, then persistent bond channels | Same RTT/loss workload; CPU/allocations/memory; ordering and no replay after lost ACK; bounded slow-node queues |
| 3: Mozilla | Capture a pinned Firefox/OS baseline, compare full TLS/H2, experiment with client Neqo | Reproducible versioned TLS/H2/QUIC captures and explicit differences; separate Neqo build/test; no Firefox parity claim from NSS alone |
| 4: access and VPN | Per-user revocation, UDP, TUN, routes/DNS/kill switch | Independent user revocation; UDP bounds; no direct-route or DNS leaks during failure |
| 5: operations | Measured useful node throughput/load, diagnostics, shutdown, field tests | Consistent anonymized Russian-operator success/recovery/RTT/throughput/CPU/memory data, including failures |

Priority 1 is implemented in this iteration: end-to-end route settings,
independent random routes for new setup clusters and inheritance on join.
Reference XHTTP interoperability, XMUX, direction-specific endpoints and arbitrary
CDN support are still not established. The test HTTPS frontend is configured
explicitly, including authentication forwarding.

The next performance work starts from known costs: one acknowledged POST per
packet-up block and one RPC per bond block. Short Go TLS loopback packet-up runs
measured 10.2–12.8 MB/s and roughly 5 MB allocated per 1 MiB exchange; these do
not measure NSS or the Internet. Limit aggregation/concurrency before comparing.

The unfinished ECH draft uses Go TLS, not NSS. It needs fail-closed credential,
key rotation, SNI/pin/cache and setup/cluster coverage before inclusion. ECH alone
does not advance Firefox fidelity.

[Mozilla Neqo](https://github.com/mozilla/neqo) provides QUIC/H3/QPACK using NSS.
Its README explicitly excludes the experimental server from production use;
client integration against our existing server should therefore come first.
The [XHTTP design](https://github.com/XTLS/Xray-core/discussions/4113) informs
transport tests; it does not establish FoxTunnel reachability in Russian networks.
