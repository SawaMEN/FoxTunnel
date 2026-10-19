# Experimental HTTP/2 receive profile

[Русский](H2-RECEIVE-PROFILE.md) · **English** · [Docs](../README.en.md)

> **Scope:** Actual HTTP/2 receive settings and Firefox-parity limits.

`--h2-receive-profile firefox-158` configures three measured receive parameters
from the [Firefox 158 Linux baseline](../research/WEB-PROFILE.en.md). This is a partial H2
experiment, not Firefox TLS, Necko or browser parity. Default remains `default`.

```sh
# An existing H2/XHTTP link may retain all endpoint/authentication settings.
./foxtunnel client --link-file connection.txt --h2-receive-profile firefox-158
# With the NSS build, keep the backend selected in the link.
# Manual client mode also accepts this flag alongside --tls-backend nss.
```

The flag is local to this client invocation and is not encoded in links or setup
bundles. It applies to outer H2 connections for h2-connect, h2-post and all three
XHTTP modes, including separate SNI/pin policies and discovered origins. Configure
it before enabling bond/discovery. It does not alter inner H2 inside XHTTP.
WSS/H3 combinations and unknown names fail explicitly, with no fallback.

| Observed client field | Default | firefox-158 | Firefox 158 baseline |
|---|---|---|---|
| SETTINGS_INITIAL_WINDOW_SIZE | 4194304 | 131072 | 131072 |
| SETTINGS_HEADER_TABLE_SIZE | default 4096, omitted | 65536 | 65536 |
| SETTINGS_MAX_FRAME_SIZE | 16384 | 16384 | 16384 |
| Initial connection WINDOW_UPDATE increment | 1073741824 | 12517377 | 12517377 |
| Effective initial connection credit | 1073807359 | 12582912 (12 MiB) | 12582912 |

The engine enforces the advertised stream window and renews stream/connection
credit as the application reads. HPACK's actual decoder table limit changes too.
Frames are not patched after creation. Go uses http.Transport.HTTP2; NSS supplies
TLS and x/net/http2 receives the same configuration through ConfigureTransports.
The NSS adapter retains its own dial-capable pool, certificate verification and
H2-only ALPN. ConfigureTransports' normal no-dial ALPN-handoff pool cannot be used
by a standalone NSS RoundTripper.

In Go 1.26.9 and x/net v0.61.0 the connection setting is **additional** credit
beyond 65535, despite the API field's maximum-buffer wording. Wire tests pin the
actual WINDOW_UPDATE and fail if a future runtime changes that interpretation.
The window is a flow-control budget, not a measurement of all process memory.
Smaller windows can reduce throughput on high-RTT routes; select explicitly and
measure your workload.

Remaining differences are deliberate and documented: ordered SETTINGS are
`2=0,4=131072,5=16384,6=10485760,1=65536`, while the Firefox baseline sent
`1=65536,2=0,4=131072,5=16384`. The 10 MiB response-header bound stays enabled.
TLS, ALPN offers, HPACK encoding behavior, header order, priority, resumption and
connection reuse still differ from Firefox. H2 is encrypted on the path; matching
these endpoint-visible values alone does not prove on-path traffic resemblance.

## Verification and captures

Tests cover real TLS/H2 wire values and more than one stream window in five
transports, Go/NSS; four simultaneous 4 MiB echoes over one verified shared outer
connection exceed 12 MiB and require real credit renewal. Cancellation releases
relays; invalid CA/SNI/pin are rejected before HTTP authorization. Unsupported
profile/transport transitions roll back without discarding the working transport.
Profile selection survives identity transport rebuilds. CLI import from stdin
accepts the local profile without disclosing the connection link.

[Go capture](../measurements/2026-10-18/foxtunnel-go-firefox158-receive.json) and
[NSS 3.98 capture](../measurements/2026-10-18/foxtunnel-nss-firefox158-receive.json)
use the same local 64 KiB XHTTP packet-up echo as the earlier candidates.

```sh
./ft-webprofile --cert /tmp/ft-research/site.pem --key /tmp/ft-research/site.key \
  --sample go --h2-receive-profile firefox-158 --transport xhttp-packet-up \
  --source 'FoxTunnel COMMIT; Go VERSION; firefox-158 receive; 64KiB echo' --out candidate.json
# Repeat with an NSS-tagged binary and --sample nss.
./ft-webprofile --input candidate.json \
  --compare docs/measurements/2026-10-18/firefox-158-linux.json --strict
# Expected failure: complete Hello/ordered SETTINGS still differ.
go test ./internal/tunnel -run '^$' \
  -bench 'BenchmarkHTTP2ReceiveProfile/.*/.*/1MiB' -benchtime=500ms -count=2
```

Short Go TLS loopback runs (two 500 ms runs per case, 1 MiB SOCKS echo, no RTT/loss)
were noisy: CONNECT default 259.82–348.32 MB/s, profile 284.20–321.72 MB/s; packet-up
default 60.98–94.14 MB/s, profile 34.44–99.50 MB/s. These do not establish a speed
advantage or Internet/NSS throughput. Next work must address the Mozilla TLS/client
stack and matched workload/RTT/loss captures, then Russian-operator field tests.
No TSPU bypass is demonstrated here.
