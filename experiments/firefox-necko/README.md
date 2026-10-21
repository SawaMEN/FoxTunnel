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

The H2 tunnel's interface map and the connect-only short-circuit in the outer
connection are candidates for a source fix. These are hypotheses until a
patched Gecko build passes the same tests. The prototype requires further
native work; switching it to Go HTTP/2 would not meet the goal.

## Checks

```sh
node --test experiments/firefox-necko/client_test.cjs
go test -race ./experiments/firefox-necko

# Expected to expose the native blocker on the stock runtime above:
FOXTUNNEL_XPCSHELL=/absolute/gecko-runtime/xpcshell \
  go test -race ./experiments/firefox-necko -run TestGeckoCONNECT -v -count=1 -timeout=80s
```

Without `FOXTUNNEL_XPCSHELL`, the native test is skipped, not passed. Parser and
configuration tests still run. Never enable raw Gecko logging with real user
traffic or credentials; native logs can include destinations and headers.

The future integration must keep certificate verification in Gecko, reject
unsupported trust settings, bound setup and queues, preserve half-close,
prevent direct/fallback leaks, and join the native process on cancellation.
