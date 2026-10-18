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

Packet-up now has a bounded four-request window, with ordered body writes,
contiguous ACK advancement and no replay. A controlled 40 ms ACK-delay benchmark
improved from 0.80 to 3.18 MB/s (256 KiB carrier echo, Go TLS, two short runs).
Full SOCKS/inner-H2 loopback runs improved from 38.44–42.78 to 95.84–96.13 MB/s;
allocated bytes fell from 5.16–5.33 to 3.69–3.87 MB per 1 MiB echo, while allocation
count increased from about 17.4k to 19.8–20.0k. These measure different workloads,
not Internet or NSS performance. Persistent bond channels remain separate work.

[Live Firefox 158 TLS/H2 captures](WEB-PROFILE.en.md) now establish explicit gaps:
NSS 3.98 and even Firefox's NSS 3.130 do not reproduce Firefox's Hello, SETTINGS
or connection window. The next Mozilla work must address actual stack behavior,
then matched traffic distributions and operator field tests. No TSPU result is
established by local captures.

The unfinished ECH draft uses Go TLS, not NSS. It needs fail-closed credential,
key rotation, SNI/pin/cache and setup/cluster coverage before inclusion. ECH alone
does not advance Firefox fidelity.

[Mozilla Neqo](https://github.com/mozilla/neqo) provides QUIC/H3/QPACK using NSS.
Its README explicitly excludes the experimental server from production use;
client integration against our existing server should therefore come first.
The [XHTTP design](https://github.com/XTLS/Xray-core/discussions/4113) informs
transport tests; it does not establish FoxTunnel reachability in Russian networks.

[A partial HTTP/2 receive profile is implemented](H2-RECEIVE-PROFILE.en.md): Firefox 158 windows and HPACK, with Go/NSS wire/credit tests. TLS, SETTINGS order and connection behavior still differ; opt-in only.

Independent distribution is a separate requirement: [versioned binaries, manifest/checksums and integration by any panel](DISTRIBUTION.en.md), [optional SDK](SDK.en.md), [wire draft](WIRE-DRAFT-0.md), MIT. Development does not depend on 3x-ui; packaging CI must assemble all nine targets before tag publication.
