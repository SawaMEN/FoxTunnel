# Next steps for FoxTunnel

[Русский](NEXT-STEPS.md) | **English**

Assessment baseline: main `b56f8e4`, 18 October 2026. Seven transports, Linux NSS
TLS, XHTTP path/Host and packet-up pipeline, a partial H2 receive profile, SDK,
cluster setup and bounded bond recovery through a common exit already exist.
Live Firefox 158/Go/NSS measurements are stored; full Firefox parity is absent.

| Stage | Work | Acceptance |
|---|---|---|
| 1. Reproducible baseline | Inspect archive contents, pin build environment, align documentation and compatibility | Both Linux NSS targets pass index and offline verify; Go/NSS/SDK checks on the same commit; experimental tag only after review |
| 2. Mozilla TLS/H2 | Address measured NSS/H2 differences; resumption/identity isolation; decide which Mozilla components are needed | Reproducible agreement/gap report against pinned Firefox/OS, matched workloads and preserved TLS checks |
| 3. Data path | Small-write coalescing, Go/C/copy profiling, persistent bounded bond lanes | Same RTT/loss workload: throughput/p95/CPU/memory; ordered duplicate-free failure handling and bounded queues |
| 4. Neqo | Mozilla QUIC/H3 client against an independent server, controlled H2 fallback | Transfer/CA/SNI/pin and blocked-UDP switching-time tests without weakening TLS policy |
| 5. Access | Per-user revocation/rotation, quotas, rate limits, safe diagnostics | One user's revocation leaves others intact; bounded resources; no secrets in logs |
| 6. Full VPN | UDP, then TUN, routes, DNS/IPv6, kill switch for the first OS | TCP/UDP policy and leak/failure/sleep/network-change tests |
| 7. Operations | Native OS tests, soak load, certificates, shutdown, updates/rollback, signing | Reproducible installation and recovery on real target systems |
| 8. Evidence/integrations | NaiveProxy comparison, operator field tests, external audit, client/panel adapters | Published data including failures, tested integrations with pinned versions |

Stage 1 adds independent checks without executing archives and
[compatibility/first-tag rules](../reference/COMPATIBILITY.en.md). Branch/PR CI builds without
publishing. Publication requires an explicit tag or a changed release request on main. Linux NSS assets bundle
hash-pinned Mozilla libraries; no macOS/Windows or Go-only release assets are published. Determine
release availability from GitHub Releases, not from the presence of a workflow.

The next concrete stage-2 task is to split the [WEB-PROFILE](../research/WEB-PROFILE.en.md)
gaps into TLS/ALPN/key shares, SETTINGS/HPACK and connection lifecycle, with a
measurement and decision for each. The receive profile already changes real
windows, but not SETTINGS order or the Necko stack. Matching NSS versions is
insufficient; a full Necko port is not yet a required architectural decision.

Firefox HTML versus TCP echo is not a disguise evaluation. Matched workloads,
external packet captures, RTT/loss, repeated connections and multiple OSes are
needed. Local packet-up/bond improvements establish no Internet advantage. The
common exit remains a failure point; lost destination TCP sockets do not migrate.
Field measurements can start earlier and repeat after changes.

Access management and platform tests can run alongside Mozilla work. ECH/REALITY,
XMUX, separate XHTTP direction endpoints and arbitrary CDNs are separate
experiments, not first-tag prerequisites. External XHTTP interoperability needs
independent wire tests. Automatic transport selection follows measurements.

Evaluate [Neqo](https://github.com/mozilla/neqo) as a client first (see [integration design](../research/NEQO-INTEGRATION.en.md)); Mozilla's
experimental server is not a production replacement for the FoxTunnel server.
Stable sing-box/Hiddify/3x-ui adapters follow stabilized contracts. No individual
stage proves Russian TSPU resistance.

## Mozilla stage-two result

[Measured TLS preferences and gap report](../research/MOZILLA-CLIENT-PROFILE.en.md):
real NSS groups/key shares/signature preferences, CLI/SDK, aligned HTML GET workload,
field-level TLS/H2 differences, reuse/cold-handshake and HRR tests. Supported groups
and key shares match; TLS1.3-only signature order and H2 SETTINGS still differ.
Necko and NSS resumption are not enabled; decisions and follow-up acceptance are
recorded in the research document. Full Firefox conformance is not claimed.

## Stage-three implementation

[Persistent channels and data-path report](../research/DATA-PATH.en.md): negotiated
bounded channels, small-write batching, mixed legacy relays, delivery-ACK loss,
entry failure, Go/NSS and transport tests, CPU/allocation/cgo/p95 measurements.
The code path is implemented. Actual packet RTT/loss, sustained/native memory and
available-bandwidth scheduling still require validation; this is not a field
performance result. Neqo remains the separate fourth stage.

Persistent channels require local `--bond-lanes` with `--bond`; RPC stays the default because throughput results are mixed.

## Stage four: implemented experimental Neqo client

The [native Neqo backend](../research/NEQO-INTEGRATION.en.md) uses pinned Rust/C
ABI 1 and NSS 3.130 against the independent Go HTTP3 server. Linux amd64 opt-in,
CA/SNI/pin before credentials, actual packet-loss/delay tests, UDP-blackhole budget,
request-free H2 fallback, SOCKS/SDK and pinned CI are implemented. Default H3 stays
quic-go; ordinary Linux NSS archives exclude Neqo. Browser fingerprint equivalence,
arm64/other OS and sustained/native-sanitizer work remain follow-up validation.

**Separate historical probe:** `experiments/neqo-ffi` remains a deliberately fail-closed Neqo UDP/QUIC experiment (Rust/C ABI v2), tested independently from the opt-in HTTP/3 implementation at `rust/neqo-bridge`. Do not confuse the two backends.

## Stage five: managed access

[Users, revocation and quotas](../reference/ACCESS.en.md): stable accounts, atomic local reload, generation-bound XHTTP/bond, live revocation, per-user/global request budgets, target-socket quota metering and conservative durable reservations. Legacy credentials remain separate. Billing periods, distributed identity sync and external audit remain future work.
