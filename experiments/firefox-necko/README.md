# Experimental Necko CONNECT runtime

Stage 2 native acceptance has passed on Linux amd64. The prototype uses real
Gecko networking for classic CONNECT over HTTP/2 and HTTP/3. It remains outside
the production CLI and SDK runtime graph. Stage 3 controlled full-Firefox CONNECT comparison has also passed; production
hardening is stage 4 in [the branch plan](../../docs/FIREFOX.md).

## Full Firefox comparison

A fresh full Firefox process and the xpcshell helper load the same pinned
libxul/NSS and execute identical raw binary CONNECT workloads. Both protocols
passed three repetitions covering cold startup, reuse, controlled reconnect,
TLS resumption and directional EOF. The measured xpcshell User-Agent discrepancy
was fixed. H2 retained fields, SETTINGS and HPACK then matched; H3 retained
fields matched except randomized extension order/JA3. H3 resumed for both clients;
H2 did not resume for either in this fixture.

[Method, observations and limitations](validation/stage3/README.md) distinguish
this raw native API reference from ordinary page navigation and stock Firefox.
The result does not establish packet-shape parity or DPI indistinguishability.

## Native acceptance

The complete `^TestGecko` suite passed three times with Go's race detector on
compiled runtime `b2d8522` and helper `0fc7192`. Its four binary hashes and
source lock were verified before recording the result. No native group skipped.

- Cold H2/H3 CONNECT handoff and binary transfer.
- Upload EOF with a complete response after half-close.
- Reverse EOF, then all 132,000 upload bytes and upload FIN. Each protocol
  covers an empty response, an 8 KiB binary response and restricted flow control.
- H2 stream credit before connection credit after exhausting the default windows;
  H3 fixed 16 KiB stream and 32 KiB connection receive windows.
- Plain local TCP output FIN while the upload half remains open.
- Untrusted roots and incorrect proxy hostnames rejected before HTTP credentials.
- Twelve simultaneously active tunnels with distinct 128 KiB binary payloads.
- Helper cancellation, listener cleanup and setup-timeout recovery in one helper.
- No TCP HTTP request when explicitly selected H3 cannot connect.

[Machine-readable results](validation/native-0fc7192.json) include the runtime
artifact, hashes, source lock, helper revision and pass counts.
[The complete native log](validation/native-0fc7192.log) records all three runs.
The fresh source build and all native CI gates passed in
[39912988779](https://github.com/SawaMEN/FoxTunnel/actions/runs/39912988779),
including three repetitions of the reverse-EOF and lifecycle gates.

## Implementation

The Go launcher starts `xpcshell` with a fresh private profile and bounded setup.
The JS adapter accepts loopback SOCKS5 CONNECT and pumps binary TCP data through
Gecko streams. HTTP/2, HTTP/3, TLS and QUIC belong to Mozilla's stack. Proxy
credentials attach to the fixed proxy, and trust/hostname verification stays in
NSS. An additional CA applies only to the helper's profile. Explicit H3 rejects
fallback and verifies the negotiated protocol before reporting SOCKS success.

The launcher sets `MOZ_DISABLE_SOCKET_PROCESS=1` before JS executes, matching
Mozilla's standalone test harness. Connect-only stream handoff is kept inside
the dedicated helper because the socket-process path does not implement it.

Native patches are combined per source file and pinned in
[gecko.lock.json](gecko.lock.json) to revision
`0f76fed7aea1f77db85afbf5a895754d8ad971d7`:

- Cold outer H2 initialization and canonical XPConnect interface identity.
- A socket-thread inline H2 copier with a 16 KiB buffer per direction and a
  per-callback work limit. H2 readiness-dependent I/O stays on the callback stack.
- Separate request/response EOF state. An established CONNECT can upload after
  response FIN; buffered response bytes drain before input EOF is notified.
- An opt-in plain-TCP half-close flag sends local output FIN without closing input.
- Classic CONNECT classification in vendored Neqo preserves the response after
  upload FIN. Its Cargo checksum changes with the patched source; integrity
  checking stays enabled and unrelated checksum entries are verified unchanged.
- H2 SETTINGS deltas and connection-window resumption include separately owned
  tunnel streams. H3 DataWritable wakes sending even if its stream is already queued.
- H3 cancellation wakes UDP output after queuing a reset on an idle connection.

The two JS pumps close their destination writer on clean EOF. Completion leaves
native copiers owning the remaining queued bytes and transports until draining
finishes. Force-closing at that point used to drop the upload tail under network
backpressure. Error and setup-timeout paths retain their abort cleanup.

CONNECT setup is serialized for both protocols; established pumps remain
concurrent. The session limit and setup deadline bound that queue. H2's per-host
pool limit follows `max_connections`, capped at Necko's native maximum of 255.
These choices affect burst timing and belong in stage 3 fingerprint measurements.
Using the Mozilla stack alone does not establish Firefox fingerprint parity.

## Build the pinned runtime

Bootstrap a clean checkout of the locked Gecko revision first:

```sh
# Run inside the Gecko checkout:
python3 mach --no-interactive bootstrap --application-choice=browser --no-agentic-tools

# Then run from FoxTunnel:
python3 scripts/build_necko.py --source /path/to/gecko --out /path/to/necko-build --jobs 2
```

The builder checks the source revision, patch hashes and exact source hashes
before and after patching. It rejects unrelated tracked changes. Applying the
same patches again is idempotent. `--prepare-only` prepares sources without
claiming compilation. This is a full C++ build; an artifact build cannot supply
the modified libxul.

Mozilla bootstrap supplies `sccache`. Hosts without that daemon can pass
`--compiler-cache none`; `--no-bootstrap-update` reuses already bootstrapped
tools. The mozconfig hash records these options. CI keeps up to 2 GiB of
compiler-cache entries without bypassing source hashes or native gates.

The [source workflow](../../.github/workflows/necko-experiment.yml) builds the
runtime and tests it. JS and Go helper changes also trigger native validation.
The reverse-EOF and lifecycle gates repeat three times. Runtime artifacts remain
available for seven days, including after a gate failure for diagnostics.
Build provenance distinguishes source preparation from compilation; native test
results are recorded separately in workflow logs.

The manual [runtime workflow](../../.github/workflows/necko-runtime-test.yml)
can reuse an artifact by source-run ID. It verifies the source lock and four
binary hashes, and rejects a runtime built with a different patch set.

## Reproduce the checks

```sh
node --test experiments/firefox-necko/client_test.cjs
python3 -m unittest discover -s scripts -p test_build_necko.py
go test -race ./experiments/firefox-necko

FOXTUNNEL_XPCSHELL=/path/to/necko-build/obj/dist/bin/xpcshell \
  go test -race ./experiments/firefox-necko -run '^TestGecko' -v -count=3 -timeout=180s
```

Without `FOXTUNNEL_XPCSHELL`, native tests skip; they do not count as passed.
A stock Gecko binary lacks the required C++ changes. Raw Gecko logging can
include destinations and headers, so the diagnostic runs use isolated fixtures.

## Remaining scope

The experimental configuration deliberately excludes SPKI pins, SNI overrides,
UDP forwarding, bonding and FoxTunnel padding. Full Necko wire comparison on
the same runtime and workload is recorded in stage 3. Sustained load, unfinished drains,
network changes, CPU/RSS, packaging and runtime upgrades are stage 4.

Earlier source run [39869936393](https://github.com/SawaMEN/FoxTunnel/actions/runs/39869936393)
compiled but exposed the 65,535-byte H2 and intermittent H3 stalls. Run
[39910478555](https://github.com/SawaMEN/FoxTunnel/actions/runs/39910478555)
supplied the corrected native runtime; restricted-window tests then identified
the JS cleanup race fixed in helper `0fc7192`. The acceptance record explicitly
identifies that runtime/helper combination rather than crediting an older binary.
