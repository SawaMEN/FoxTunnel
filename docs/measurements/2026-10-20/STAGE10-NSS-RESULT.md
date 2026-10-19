# Stage 10: current NSS/H2 capture result and evidence limits

- Code commit: 0f654d876d48cef4a29316b430620e955242dd6c
- Source: real live local TLS/H2 capture with pinned NSS 3.130
- CI: https://github.com/SawaMEN/FoxTunnel/actions/runs/39327264239
- CI artifact: stage10-current-nss-h2-vs-historical-firefox-not-naive
- Reference: docs/measurements/2026-10-18/firefox-158-linux.json
- Context: controlled H2 HTML GET on current FoxTunnel; Firefox 158 reference
  from an older capture, not a simultaneous network test

## Verified comparison

| Category | Equal | Different | Not observed | Not measured |
|---|---:|---:|---:|---:|
| TLS fields | 6 | 6 | 1 | 0 |
| HTTP/2 fields | 7 | 0 | 0 | 0 |
| QUIC/HTTP3 fields | 0 | 0 | 0 | 5 |

The current actual NSS/H2 initial SETTINGS capture was:

- HEADER_TABLE_SIZE 65536 (id 1)
- ENABLE_PUSH 0 (id 2)
- INITIAL_WINDOW_SIZE 131072 (id 4)
- MAX_FRAME_SIZE 16384 (id 5)
- Connection initial WINDOW_UPDATE: 12517377

Those observed values and their order agree with saved Firefox-158 H2 initial
metadata. This is **not** the same as Firefox H2 framing over a complete
browser session, HPACK, traffic shape, TLS parity or DPI bypass.

TLS still disagrees on cipher suites, ordered extensions, supported versions,
signature algorithms, offered ALPN and JA3. One field (EC point formats)
was not observed in the candidate profile, so it is not called equal.

**NaiveProxy was not captured.** Missing NaiveProxy is not a pass.
QUIC/H3 settings and client packet behavior were not captured for any
of the three subjects for controlled equivalence evaluation.

Artifacts expire under CI retention; this summary records observed counts
and fields with a link to the actual workflow.
