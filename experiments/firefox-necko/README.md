# Necko CONNECT research prototype

**Blocked experiment. Not included in `foxtunnel` or its SDK runtime graph.**

The prototype runs actual Gecko networking through `xpcshell` and a fresh private
profile. It does not synthesize HTTP/2 in Go. The SOCKS adapter, bounded stream
copies and process launcher are present, but the native CONNECT handoff has
not passed the end-to-end gate. Do not use it as a working Firefox transport.

## What was tested

Linux amd64 Mozilla CI runtime:

- Task: `e2JM7VtaRWmm7wOrhkX-GA`, run 0.
- Build ID: `20261021092254`, Firefox `160.0a1`.
- Source: mozilla-central `f62de275299e8e64e7cb1ee2dd76e025f255beba`.
- Matching `target.tar.xz` and `target.common.tests.tar.zst`; the latter supplies
  `bin/xpcshell`, which is not part of the ordinary Firefox installation.

Observed failures:

1. A fresh H2 proxy session created by a connect-only transaction is closed
   before the destination CONNECT is submitted (`NS_ERROR_NET_RESET`).
2. A normal anonymous request can initialize the outer session. The subsequent
   authority-form CONNECT reaches the independent Go server, but the C++ to JS
   `onTransportAvailable` handoff fails before the JS callback executes.
   Warming up is a diagnostic only and is absent from the committed prototype.
3. The H3 end-to-end test did not pass either. It must not be inferred from
   Neqo's separate interoperability tests or an H2 fallback.

## Pinned source build

The candidate fixes are now in [patches](patches/), pinned by
[gecko.lock.json](gecko.lock.json) to Git revision
`0f76fed7aea1f77db85afbf5a895754d8ad971d7`. This is a separate source build;
do not attribute its results to the stock Taskcluster binary above.

- The outer H2 session must not take the connect-only early-close path. That
  path still applies to the inner tunnel connection.
- `Http2StreamTunnel::QueryInterface` delegates unknown interfaces to its base,
  preserving the base's canonical `nsISupports` identity for XPConnect. The
  duplicate `nsITransport` map entry is removed.

These are candidate native fixes until the patched build passes the tests.
Half-close also requires validation: the existing native output tunnel close
paths tear down the stream, so a successful handoff alone is insufficient.
The prototype remains excluded from the production CLI and SDK.

The [Necko source workflow](../../.github/workflows/necko-experiment.yml)
bootstraps Mozilla's C++ build dependencies, builds libxul and xpcshell, then
runs two mandatory native gates: cold handoff/binary transfer, followed by
the full half-close contract. Neither gate is a mock or an H2 fallback claim.
Both gates run if compilation succeeds, even if the handoff test fails.
Build provenance distinguishes source preparation from a compiled runtime;
interop results remain in the workflow logs. Runtime artifacts are retained
for seven days so the same compiled build can be diagnosed without rebuilding.

To reproduce with a clean, shallow checkout of the locked Git revision:

```sh
# First bootstrap inside that checkout:
python3 mach --no-interactive bootstrap --application-choice=browser --no-agentic-tools

# Then from FoxTunnel; paths must be absolute or relative to this directory:
python3 scripts/build_necko.py --source /path/to/gecko --out /path/to/necko-build --jobs 2
```

The builder rejects revision drift, unrelated tracked changes, source drift,
and patch digest mismatches. Applying the exact patches again is idempotent.
`--prepare-only` validates/applies source changes without claiming compilation.
This is a full C++ build; Mozilla artifact builds cannot apply these fixes.

## Checks

```sh
node --test experiments/firefox-necko/client_test.cjs
python3 -m unittest discover -s scripts -p test_build_necko.py
go test -race ./experiments/firefox-necko

# Expected to expose the native blocker on the stock runtime above:
FOXTUNNEL_XPCSHELL=/absolute/gecko-runtime/xpcshell \
  go test -race ./experiments/firefox-necko -run TestGeckoCONNECT -v -count=1 -timeout=80s

# Same gates with the patched source build:
FOXTUNNEL_XPCSHELL=/path/to/necko-build/obj/dist/bin/xpcshell \
  go test -race ./experiments/firefox-necko -run TestGeckoCONNECT -v -count=1 -timeout=160s
```

Without `FOXTUNNEL_XPCSHELL`, the native test is skipped, not passed. Parser and
configuration tests still run. Never enable raw Gecko logging with real user
traffic or credentials; native logs can include destinations and headers.

The future integration must keep certificate verification in Gecko, reject
unsupported trust settings, bound setup and queues, preserve half-close,
prevent direct/fallback leaks, and join the native process on cancellation.
