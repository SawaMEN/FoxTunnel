# Opt-in Necko distribution and operational qualification

The target is Linux amd64. This launcher is separate from the ordinary FoxTunnel
CLI/SDK. It runs xpcshell in a dedicated process and private temporary profile.
The four-stage branch plan does not promise indistinguishability or deployment
qualification on every network. Native acceptance for the current source lock
must pass before distributing a bundle built from it.

## Session ownership and limits

The helper bounds setup, established idle time and retained native drains.
Setup remains serialized; established streams transfer concurrently. Progress in
either direction refreshes the established idle deadline using a monotonic clock.
A completely idle tunnel expires, including a stalled peer or broken path.

Both JS pumps close their destination writer on clean EOF. Native pipe copiers
can still own queued bytes. Clean sessions therefore move into a retained set;
they are not force-closed at JS completion. A configured drain deadline later
aborts any remaining native work and releases retained references. The native
handoff API does not expose copier completion, so this retention is deliberately
conservative even when the stream has already finished.

Admission reserves space for every active session in the retained budget. Thus
`active <= max_connections` and `active + draining <= max_retained_connections`
always hold, including simultaneous completions. A full budget refuses new TCP
clients until space returns. Completed-connection churn consumes retained slots
for the full drain interval; size this budget with the expected churn rate.
Reducing the drain interval also reduces the time allowed for queued bytes on a
slow path. Timeout cancellation never replays an interrupted application stream.

| JSON option | Default | Accepted values |
| --- | --- | --- |
| `max_connections` | 256 | 1–4096 |
| `max_retained_connections` | `min(4 * max_connections, 4096)` | `max_connections`–16384 |
| `connect_timeout_ms` | 15000 | 100–120000 |
| `idle_timeout_ms` | 300000 | 100–86400000 |
| `drain_timeout_ms` | 30000 | 100–120000 |
| `stats_interval_ms` | 0 (off) | 0 or 100–60000 |

JSON-line `stats` output contains active/draining counts, completions, refusals,
idle/drain expirations and upload/download byte counters. It contains no
credentials or destinations. `gc_collections` and `gc_ms` report the helper's
retired-object GC/CC maintenance and cumulative wall time in milliseconds. After
at least 64 retirements, it runs at most once per five seconds to bound retained
JS/XPCOM callback cycles in the embedded shell. Live streams remain rooted;
HTTP/TLS caches are not cleared. This may briefly pause the JS thread and its
CPU cost is included in the soak measurements.

Byte counters count JS pump progress, not peer
acknowledgments. `ready.pid` is the process's own PID namespace; `process_tag`
identifies its unique private profile for diagnostics in containers. The helper
profile is removed after process termination/join.

## Build and verify a bundle

Use a **dereferenced** compiled runtime artifact and its build provenance from
this branch's source workflow. An arbitrary Firefox install or stock xpcshell
will not supply the pinned patches. The package builder verifies the exact
source lock and four compiled binary hashes before copying files. Symlinks,
special files and output paths inside the source runtime are rejected.

```sh
go build -trimpath -ldflags='-s -w' -o necko-launcher \
  ./experiments/firefox-necko/cmd/foxtunnel-necko
python3 scripts/package_necko.py \
  --runtime /path/to/dereferenced-runtime \
  --provenance /path/to/provenance.json --launcher ./necko-launcher \
  --out ./necko-version-1 --archive ./foxtunnel-necko-linux-amd64.tar.gz
./necko-version-1/foxtunnel-necko --bundle "$PWD/necko-version-1" --verify
```

The bundle includes the launcher, full compiled runtime, source lock/provenance,
source patches and dependency license notices. It retains the complete runtime
resource layout rather than guessing which files can be removed. The manifest
hashes every file and binds the helper protocol, embedded JS and native source
lock. Startup rejects altered, missing or extra files and incompatible helper
versions. Keep configuration and logs **outside** this immutable directory.
Checksums detect corruption; obtain the archive digest from trusted CI or your
own build. They do not authenticate an untrusted publisher.

The CI artifact `foxtunnel-necko-linux-amd64` contains the `.tar.gz` bundle and
`SHA256SUMS`. The runtime workflow rechecks the source lock and binary hashes,
performs native and operational gates, then tests real H2/H3 transfer and SIGTERM
through the packaged executable from an unrelated working directory.

## Run

The CI host uses Ubuntu 24.04 with `libgtk-3-0t64`, `libdbus-glib-1-2`,
`libasound2t64` and `libxt6`. Other distributions need equivalent runtime
libraries. The bundled Gecko/NSS libraries are selected from the bundle.

Create a private configuration beside the extracted bundle, not inside it:

```json
{
  "server": "https://proxy.example.com",
  "username": "your-user",
  "password": "your-password",
  "transport": "h3-connect",
  "listen": "127.0.0.1:1080",
  "max_connections": 256,
  "max_retained_connections": 1024,
  "idle_timeout_ms": 300000,
  "drain_timeout_ms": 30000,
  "stats_interval_ms": 10000
}
```

```sh
chmod 600 client.json
./foxtunnel-necko/foxtunnel-necko --config "$PWD/client.json"
```

Use `h2-connect` explicitly for H2. Explicit H3 has no TCP fallback. Additional
trust roots can be supplied through `ca_cert`; hostname and chain verification
remain mandatory. The SOCKS listener is loopback-only and does not resolve
application destinations locally. SIGTERM/Ctrl-C cancels and joins the helper.

## Updating and rollback

Build/download a new bundle in a new directory, verify its archive checksum and
run its own `--verify` before switching. Its embedded helper, source lock and
manifest must agree. Do not replace libraries under a running process. Stop the
launcher, select the new directory and start it with the same external config.
Keep the previous complete directory until the new version is qualified; rollback
uses that directory's own launcher. Existing TCP streams end during a restart;
application data is not replayed into a new connection.

Updating the Mozilla revision or native patches requires source hash review,
full compilation, all native gates, the Firefox comparison and operational gates.
A helper-only change can reuse compiled artifacts **only** when the full native
source lock matches. The runtime workflow waits for matching compilation rather
than using an older binary. A changed embedded JS or bundle protocol requires
repackaging and a corresponding helper; mixed versions are rejected.

## Operational tests

```sh
FOXTUNNEL_XPCSHELL=/absolute/path/runtime/xpcshell \
  go test -race ./experiments/firefox-necko \
    -run '^Test(GeckoIdleAndDrainLimits|GeckoNetworkRecovery|NetworkRelayPeers|Bundle|Lifetime)' \
    -count=3 -v -timeout=180s
FOXTUNNEL_XPCSHELL=/absolute/path/runtime/xpcshell \
FOXTUNNEL_SOAK_SECONDS=300 FOXTUNNEL_OPERATIONS_OUT=/absolute/path/observations \
  go test -race ./experiments/firefox-necko -run '^TestGeckoSoak$' -count=1 -v -timeout=720s
FOXTUNNEL_BUNDLE=/absolute/path/bundle \
  go test -race ./experiments/firefox-necko -run '^TestGeckoPackagedLauncher$' -v -count=1
```

The soak warms the helper with 16 verified tunnels, then repeatedly opens eight
concurrent 128 KiB binary tunnels with directional EOF. It records helper-process
RSS, file descriptors and CPU ticks/seconds/utilization, excluding the Go proxy
and fixture process. Linux `/proc` counters and the host `CLK_TCK` define units.
Resource growth thresholds compare the post-warm baseline with the drained end;
all intermediate samples are retained. They are regression limits, not a
universal memory or performance guarantee.

The network fixture drops the controlled loopback path, verifies bounded failure
and restores new CONNECTs in the same helper. H3 also changes the upstream UDP
source port while an application stream remains open, exercising NAT rebinding.
This does not simulate a change of the proxy's IP address, IPv4/IPv6 switching,
a mobile operator handoff or packet-loss distributions on the Internet. Those
scenarios and multi-day reliability require deployment-specific pilot testing.
