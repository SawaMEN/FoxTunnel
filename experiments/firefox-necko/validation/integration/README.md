# Main CLI and SDK Necko integration

This record covers the Linux amd64 `necko` engine in the main FoxTunnel CLI and
Go SDK, on branch `firefox`. The qualified code is
`12414b0ae84f0afbfae43db3ae2a6584bcdb2abd`; production implementation entered in
`043de8363fecdeff613c960d4a5a0b6f0812cbf3`. Later changes tightened the dependency
allowlist and corrected a negative-test assumption without changing that runtime
implementation.

[Runtime CI 40021334528](https://github.com/SawaMEN/FoxTunnel/actions/runs/40021334528)
passed all gates; the complete [workflow log](workflow.txt) is retained. It
checks the pinned native runtime from source build `39952039057`, artifact
`12501945687`. [Runtime provenance](../stage4/runtime-provenance.json) identifies
the native source lock and binary hashes. The current helper and fixture hashes
are recorded in [wire-summary.json](wire-summary.json).

## Integrated behavior

The main CLI starts Necko with `--engine necko`; the SDK starts it during
`NewClient` with `Engine: "necko"` and `NeckoBundle`. Both verify the immutable
bundle, own one helper, wait for readiness and join it during shutdown. Remote
TLS, HTTP/2 and HTTP/3 run in Mozilla. The Go adapter uses authenticated local
SOCKS IPC, with a fresh secret kept outside argv and public status.

The integrated native gates test both protocols through the actual packaged main
CLI and public SDK: binary transfer, half-close, setup-context cancellation,
capacity, status, owned shutdown and listener/profile cleanup. Anonymous IPC and
incorrect credentials are refused before any HTTPS request reaches the proxy.
A refusal may close the local socket before a negative SOCKS frame is flushed;
the test accepts immediate EOF, requires zero proxy requests and separately
requires successful authorized binary transfer. That test also passed ten local
repetitions with the race detector.

The runtime workflow additionally checks native trust/cancellation/flow control,
controlled network interruption and H3 NAT rebinding, immutable packaging and
standalone packaged transfer/shutdown. Its 300-second-per-protocol resource gate
measures the native helper under eight concurrent 128 KiB transfers; it is not a
separate 300-second SDK or main-CLI endurance test. Exact results and artifact
identity are in [acceptance.json](acceptance.json). H2 completed 13,744 measured
transfers; H3 completed 13,056. Both ended with the baseline 45 descriptors.
Warmed-to-final RSS was 122,552 → 241,660 KiB for H2 and 131,772 → 244,472 KiB
for H3, within the unchanged 192 MiB growth bound.

The [verified bundle](https://github.com/SawaMEN/FoxTunnel/actions/runs/40021334528/artifacts/12532075725)
contains the main CLI, standalone launcher and native runtime. CI artifact
retention ends on 2026-11-06; this is a branch build, not a tagged release.

## Wire comparison and control

Each corpus contains three fresh repetitions per protocol, with two connections
per subject. The reference uses the same patched libxul and CONNECT API in a full
Firefox process. Raw observations are retained in `standalone/`, `managed/` and
`firefox-self/`; summary differences are never suppressed.

| Comparison | H2 repetitions with raw HPACK/frame differences | H3 repetitions with TLS extension-order/JA3 differences |
| --- | ---: | ---: |
| Standalone helper versus Firefox | 3/3 | 3/3 |
| Managed engine versus Firefox | 1/3 | 3/3 |
| Firefox versus Firefox | 2/3 | 3/3 |

Decoded headers and extension sets agreed throughout. The H2 variation is
consistent with SETTINGS ACK scheduling and Mozilla's pending HPACK size update;
the stored HPACK hashes do not prove that causal attribution. H3 extension order
varies in both subjects. The implementation preserves Mozilla scheduling and
randomization. These small samples establish neither byte identity nor equality
of distributions, and they are not a DPI indistinguishability test.

To regenerate full reports from the retained raw observations:

```sh
python3 scripts/compare_necko_firefox.py --observations experiments/firefox-necko/validation/integration/standalone --out /tmp/necko-standalone.json
python3 scripts/compare_necko_firefox.py --observations experiments/firefox-necko/validation/integration/managed --out /tmp/necko-managed.json
python3 scripts/analyze_firefox_self.py --observations experiments/firefox-necko/validation/integration/firefox-self --out /tmp/necko-self.json
```

## Scope

The qualified distribution is Linux amd64. UDP, padding, Bond/discovery,
fallback/balancing, XHTTP, strict draft negotiation and manual TLS/QUIC/SNI/SPKI
profile overrides are rejected. CA trust remains supported. No stock-browser,
ordinary-navigation, mobile-handoff, multi-day reliability or arbitrary Internet
path claim is made. [Usage and lifecycle](../../INTEGRATION.md) document the
supported CLI and SDK configuration.
