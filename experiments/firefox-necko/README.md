# Necko CONNECT research prototype

**Blocked experiment. Not included in `foxtunnel` or its SDK runtime graph.**

The prototype runs actual Gecko networking through `xpcshell` and a fresh private
profile. It does not synthesize HTTP/2 in Go. The SOCKS adapter, bounded stream
copies and process launcher are present. Native H2/H3 handoff and binary
transfer have passed, but response truncation and half-close regressions still
block the complete gate. Do not use it as a production Firefox transport.

## Initial stock-runtime diagnostics

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
- The JS upgrade's H2 pipes use an inline copier on the socket thread. Native
  H2 Read/Write require the native readiness callback to remain on the stack;
  `NS_AsyncCopy` defers that operation and repeatedly gets WOULD_BLOCK. The new
  copier retains at most 16 KiB per direction, handles partial writes, and
  limits work per callback. It is selected only for the raw H2 tunnel.
- A clean output EOF closes only the sending side of H2/H3; errors still abort
  the stream. Vendored Neqo receives the same classic CONNECT classification
  fix as the separate Neqo bridge, so its response survives upload FIN.
  Its `.cargo-checksum.json` entry is updated by a separate pinned patch;
  Cargo's integrity checks remain enabled. The regression check verifies that
  all other checksum entries and the package checksum are unchanged.
- Plain TCP gains an opt-in `ENABLE_TCP_HALF_CLOSE` connection flag. On clean
  output closure it sends `PR_SHUTDOWN_SEND` after buffered output drains,
  leaving input open. The SOCKS adapter sets it only on the accepted local
  socket, before opening streams. Layered sockets and sockets without the flag
  retain their existing close behavior; shutdown errors still abort normally.
- H3 tunnel cancellation wakes UDP output after queuing a reset. Its cleanup
  calls `CloseStream` directly, bypassing `CloseTransaction` and that method's
  `ResumeSend`. The candidate wakes output only when tunnel cleanup actually
  queued `CancelFetch`, so an idle connection can send the reset promptly.

The stream-copy and EOF changes are candidates until a new source build passes
the tests. The prototype remains excluded from the production CLI and SDK.

## Results on the first compiled runtime

Source workflow run `39685378279`, commit
`47a2586cee6a9244c90be53fc0f850b82729b5f1`, successfully compiled Gecko with
the cold-start and identity fixes. Its first tests timed out before readiness.
Native thread stacks from runtime gate run `39729125556` identified a startup
deadlock: the profiler's download-directory lookup initialized HTTP and tried
to launch the socket process before client JS could set its preferences.

The launcher now sets `MOZ_DISABLE_SOCKET_PROCESS=1` before starting xpcshell,
matching Mozilla's own standalone test harness. No profiler or certificate
checks are disabled. The environment setting is needed before any script runs.

Using that exact compiled artifact, with the launcher/JS corrections:

- **H3 cold handoff and binary transfer passed locally with `-race`.** Two
  authority-form CONNECTs delivered binary payloads through an independent
  Go H3 server. An explicitly supplied CA also requires turning off Firefox's
  automatic H3 fallback for third-party roots; NSS still validates the chain
  and proxy hostname.
- H2 native handoff succeeded, but payload stalled. The native trace identified
  the deferred-copier mismatch described above. The inline copier needs a new
  compiled runtime to validate it.
- H3 upload half-close returned an empty response. The native EOF and vendored
  Neqo fixes above need a new compiled runtime too.
- Separate native trust tests reject both an untrusted root and a wrong proxy
  hostname before any HTTP request reaches the proxy. A setup timeout may end
  with a closed SOCKS socket; it must never report success.

These observations do not close the full H2/H3 gate. In particular, reverse
half-close and the new H2 stream copier still need native verification.
Concurrency, cancellation under load, and protocol fallback
must be verified before promotion.

## Additional lifecycle gates

Source run `39731105034` stopped at Cargo's integrity check before the new
libxul was built: the patched vendored Rust source still had its upstream
checksum entry. The source lock now includes the matching checksum patch;
this failure is not a native interop result.

The additional native tests use a real TCP echo destination and an independent
Go proxy. On the first compiled runtime, with the updated JS adapter, local
`-race` runs confirmed:

- Twelve simultaneously active H3 CONNECTs, each carrying a distinct 128 KiB
  binary payload containing every byte value; repeated three times.
- Cancellation joins the helper, closes the active local stream and removes
  the SOCKS listener; repeated three times.
- A TCP/H2-only proxy receives zero HTTP requests when H3 is explicitly
  selected and its QUIC endpoint is unavailable.

Cold parallel H2/H3 setup previously caused handoff failures. The
adapter now queues CONNECT setup for both transports, while established streams keep independent
concurrent pumps. The existing connection limit and per-session setup timeout
bound that queue. This adds setup latency to a burst of new tunnels and must
be included in stage 3 timing comparisons. The adapter also disables H3 error
fallback preferences and delays the TCP backup beyond the setup deadline.
The protocol check on handoff remains in place. For H2, the destination pool
limit follows `max_connections`, capped at Necko's native per-host maximum of
255. The helper still enforces its own total session limit. This changes
burst scheduling and must be included in fingerprint comparisons.

The new source build runs these lifecycle gates for **both** H2 and H3, in
addition to upload EOF and certificate checks. Success on the earlier H3
artifact does not count as verification of the new C++/Rust patches.

### Pending setup cancellation and recovery

`TestGeckoCancellation/setup-timeout-recovery` uses one helper with a single
allowed connection. The proxy withholds response headers for two CONNECTs;
each setup deadline must reset its request stream at the peer. A third CONNECT
must then establish and deliver 36,000 binary bytes through the same helper.
This exposes leaked slots and a stuck H3 setup queue. It is included in the
source workflow's existing repeated cancellation selector.

`TestSetupCancellationPeers` independently confirms that the H2/H3 fixture sees
a reset from Go clients; three local `-race` repetitions passed. The handler
reads the request body to observe reset directly instead of relying solely on
an H3 request context notification.

On runtime `47a2586`, H3 timed out waiting for that peer reset. Native logging
showed channel cancellation and tunnel `CloseStreamInternal`, but no subsequent
output processing. Source inspection identified the missing wake-up described
above. The new patch is a candidate until a matching compiled runtime passes;
the older runtime's result does not validate it.
On the same runtime, H2 reset both pending requests and opened the third
CONNECT, then stalled during binary transfer at the previously identified
copier blocker. That is a failed end-to-end gate, not a recovery success.

## Reverse half-close gate

`TestGeckoReverseHalfClose` checks the other EOF direction independently: the
proxy sends its response FIN first, then must receive all 132,000 binary upload
bytes and the client's FIN. Each protocol runs both an empty response and an
8 KiB binary response before FIN, so buffered tail data must survive EOF too.
The H2 fixture uses a TLS/HPACK/frame peer; the H3
fixture takes over the QUIC stream so sending FIN does not finish the handler
and cancel the request. Neither fixture dials the dummy CONNECT destination.
`TestReverseHalfClosePeers` validates both fixtures with independent Go clients;
both passed locally with the race detector.

On the first compiled runtime (`47a2586`), both native modes timed out waiting
for response EOF. An isolated native socket probe found another blocker:
`nsSocketTransport` output closure does not send TCP FIN while input remains
open. The probe received its response marker and could upload afterward, but
the TCP peer timed out waiting for EOF. This occurs without HTTP or a proxy.
`TestGeckoLocalHalfClose` now checks that contract independently: buffered data,
response FIN, then a complete upload and upload FIN on the same socket.

The opt-in socket patch is a candidate until the new source runtime passes.
The adapter's feature guard preserves older runtimes for blocker diagnostics;
it does not make those runtimes pass the half-close gates. The earlier source
build at `97bcf1d` predates this patch. New source runs preserve an already
running build instead of cancelling it on a push.
Both EOF directions must pass before promotion; fixing the local FIN does not
establish correctness of native H2/H3 receive-side stream cleanup.

The receive-side candidates now preserve an established H2 tunnel in the
session tables until upload finishes, using the existing deferred-cleanup
contract. A response FIN no longer blocks tunnel writes. Clean input closure
does not reset the output half; errors still abort. H3 likewise waits for both
directions before reporting the stream done, delivers buffered bytes before
notifying input EOF, and keeps request writes valid after response FIN.
These changes require a matching compiled runtime to validate.

## Source compilation blocker

Source runs `39733228026` (`97bcf1d`) and `39736309532` (`fa254f7`) both
stopped compiling `nsHttpConnectionMgr.cpp`: the copier patch included
`mozilla/Unused.h`, which is absent at the pinned Gecko revision. Neither run
produced the new runtime or executed native interop gates. The copier now uses
explicit `(void)` casts for discarded results and does not need that header.
Its patch and resulting-source hashes have been updated. This corrects the
reported build error; compilation and native gates still require a new run.

The separate Neqo workflow at `39857861899` passed native interop but failed
before wire capture because upstream removed the `v154.0.8037.49-4` binary
assets (HTTP 404). The comparison input is now explicitly pinned to
`v154.0.8037.49-5`, source `d04efe1ea4477c2db24a7d0e2f068b3bee931e45`.
The Linux x64 archive was downloaded and its SHA-256 matched the upstream
release asset digest; the executable reports `naive 154.0.8037.49`.
Historical captures retain their original pins and results. New captures must
be regenerated with the new archive; this does not validate Necko's fingerprint.
Run `39861472512` completed successfully with the updated pin, including fresh
wire observations and comparison. Those results concern the separate NSS/Neqo
adapter; the full Necko prototype remains blocked by its native gates.

The [Necko source workflow](../../.github/workflows/necko-experiment.yml)
bootstraps Mozilla's C++ build dependencies, builds libxul and xpcshell, then
runs five mandatory native gates: cold handoff/binary transfer, upload
half-close, rejection of invalid certificates before credentials, local TCP FIN
and reverse half-close, and repeated concurrency/cancellation/H3-only checks.
These are real native tests; none counts an H2 fallback as H3 success.
The latter gates run if compilation succeeds even if handoff fails.
Build provenance distinguishes source preparation from a compiled runtime;
interop results remain in the workflow logs. Runtime artifacts are retained
for seven days so the same compiled build can be diagnosed without rebuilding.
The manual [runtime gates workflow](../../.github/workflows/necko-runtime-test.yml)
accepts a source workflow run ID and verifies its source lock and binary hashes
before reusing the artifact. It refuses a runtime from a different patch set.

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
Mozilla bootstrap supplies the compiler cache used by `--with-ccache=sccache`.
Hosts without a compiler-cache daemon can use `--compiler-cache none`.
After bootstrapping the pinned tools, `--no-bootstrap-update` reuses them
without another download. Both options are recorded in the mozconfig hash;
they do not enable artifact substitution or relax source validation.
CI retains up to 2 GiB of compiled C/C++ entries, including after a failed
build or native gate, so a later correction can reuse unchanged compilations.
Cache reuse does not bypass source/patch hashes or native gates; cache statistics
are printed by the build. The first build with an empty cache remains cold.

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
  go test -race ./experiments/firefox-necko -run '^TestGecko' -v -count=1 -timeout=180s
```

Without `FOXTUNNEL_XPCSHELL`, the native test is skipped, not passed. Parser and
configuration tests still run. Never enable raw Gecko logging with real user
traffic or credentials; native logs can include destinations and headers.

The future integration must keep certificate verification in Gecko, reject
unsupported trust settings, bound setup and queues, preserve half-close,
prevent direct/fallback leaks, and join the native process on cancellation.

## Native validation update (5c7e200 runtime)

Source run `39857862006` completed its full Gecko build. Native gates passed
H2/H3 cold handoff and binary transfer, H2 upload EOF, certificate rejection,
and local TCP FIN. They exposed H3 response truncation and loss of uploads
after reverse EOF in both protocols. The current source patches address those
failures; the stage remains open until the rebuilt runtime passes them.

With the current JS setup queue and H2 pool limit, the same compiled runtime
passes twelve simultaneous CONNECTs with distinct binary payloads for H2
and H3, three repetitions under Go's race detector. This validates the JS
setup correction, but does not validate the additional native EOF patches.
