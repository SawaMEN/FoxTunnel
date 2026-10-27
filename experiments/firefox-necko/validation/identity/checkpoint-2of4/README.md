# Stage 5: failed qualification checkpoint (2/4)

This is preserved failure evidence, not acceptance. Native source run
[40317262284](https://github.com/SawaMEN/FoxTunnel/actions/runs/40317262284)
compiled the same 28-patch lock on AMD64 and ARM64. ARM64's 60-second resource
gate failed with H2 RSS 141672 -> 359048 KiB and H3 148420 -> 364592 KiB,
against the unchanged 192 MiB growth bound. Completed tunnel and byte counters
matched; file descriptors stayed at 46. These observations do not prove a leak.

Runtime run [40317917970](https://github.com/SawaMEN/FoxTunnel/actions/runs/40317917970)
failed ARM64's strict wire audit. The three candidate trials had H2 SETTINGS ACK
and HPACK table-size update timing differences in two observations, which the
three self-control observations did not capture. The full raw comparison and
self-control values are retained in the JSON reports. No field was normalized
or declared equivalent. H3 extension-order differences remained inconclusive.

A local rebuilt AMD64 profile gate also found that its expected signature list
had omitted NSS's TLS-1.3 filtering: PKCS#1 certificate schemes are moved last.
The native preset already matches the existing NSS profile gate. Candidate
`23c4eb6` corrects that expectation, adds a context-exhaustion assertion to
negative identity gates, releases unused shell arenas after cycle collection,
and runs nine candidate / nine self-control repetitions with strict enforcement.

These files remain historical after later qualification. See
[the current checkpoint](../progress.json) for current status.
