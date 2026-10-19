# Unified Mozilla Transport Engine — Stages 1–2

Stage 1 is a **local client configuration/selection layer**, not a change to
FoxTunnel's wire protocol, credential format, servers, or existing Go backends.

## Use

Linux with a Mozilla NSS build is required. The Neqo H3 adapter is currently
experimental and available only with the Linux amd64 nss,neqo build.

~~~sh
# With an existing connection link: preserve its specified transport.
foxtunnel client --engine mozilla --link-file connection.txt

# With explicit server credentials configured in the environment:
# choose H3/Neqo if compiled, otherwise H2/NSS.
foxtunnel client --engine mozilla --server https://proxy.example

# Explicitly require H3; no silent transition to quic-go.
foxtunnel client --engine mozilla --server https://proxy.example --transport h3-post
~~~

A program embedding the Go SDK sets ClientConfig.Engine = "mozilla".
The same policy resolver is shared by CLI and SDK in
internal/transportengine/engine.go. Empty/legacy preserves previous defaults.
The client flag is **local** and is not embedded into vetroff:// links.

## Selection and security contract

- Mozilla mode requires an NSS-enabled build; ordinary Go-only builds fail
  explicitly. Legacy defaults remain unchanged.
- For transport auto (or unset SDK transport), prefer Neqo/H3 when compiled,
  otherwise NSS/H2. A connection link preserves its declared transport.
- H3 always requires Neqo, its native TLS 1.3 and HTTP/3, and optional H2/NSS
  fallback (enabled by default in Mozilla H3). It does not accept TCP-only
  Firefox client or H2 receive profiles.
- The existing Neqo fallback is limited to transport reachability errors
  **before** creating an HTTP stream. It never follows TLS trust, pin, ALPN,
  HTTP status, authorization or mid-stream errors.
- H2, XHTTP and WSS use NSS with the measured Firefox 158 TLS profile.
  Outer H2 modes also select the Firefox 158 receive-window profile.
  The WSS outer connection is HTTP/1.1, so it does not use that H2 profile.
- NSS certificate verification and pinning are unchanged. Incompatible builds
  or explicitly conflicting backends fail; no hidden Go TLS downgrade.
- Running both H2 and H3 requires the server to listen on TCP/UDP. For H3
  fallback the server also needs to support H2 on the same origin.
- H3->H2 fallback currently uses the existing default NSS H2 settings, not
  the full Firefox 158 H2 profile. Closing this gap belongs to later stages.

This is **not** the Firefox Necko stack, browser fingerprint parity, TUN/UDP
application support, or proven DPI bypass. See
docs/research/MOZILLA-CLIENT-PROFILE.md and
docs/research/NEQO-INTEGRATION.md for measured limitations.

## Compatibility

The server, CLI setup/share workflow, legacy transport selection, and public
SDK fields remain available. Engine selection is local to the client and
requires no migrations to connection links or server configurations.

Stage 1 intentionally does not add or run tests. Changes must be validated
before release.

## Stage 2: standard Mozilla distribution flavor (build only)

A separate `linux/amd64/mozilla` binary distribution can now be assembled
directly by `scripts/build_mozilla.py`. Unlike regular `nss` archives, this
variant is compiled with `-tags nss,neqo,mozilla` and therefore includes
Go Core, real NSS TCP TLS, and the Neqo QUIC/H3 Rust static adapter together.

The bundled NSS/NSPR/SQLite dynamic runtime is pinned to Firefox 158.0
(NSS 3.130); Neqo 0.33.0, nss-rs, Rust 1.99.1 and the source revisions are
locked in `scripts/neqo.lock.json` and Cargo.lock. A single application
binary is provided alongside the pinned `lib/` directory: removing the
shared libraries breaks TLS. No running sidecar is required.

~~~sh
# Linux amd64 prerequisites documented in scripts/build_neqo.py
python3 scripts/build_mozilla.py --version v0.0.0-ci

# After extracting the generated archive:
./foxtunnel client --engine mozilla --server https://proxy.example
~~~

The **Mozilla unified bundle (build only)** workflow is defined for manual
GitHub Actions use. GitHub requires a manually dispatched workflow to exist
on the repository's default branch; until that happens, run the build script
locally from `update`. Once available on the default branch, select `update`
when starting the workflow. It uploads the .tar.gz bundle and .metadata.json. This is **not a GitHub Release**. The existing
`release.yml` still produces its original two NSS targets and keeps its
existing versioned release checks. No tests were added or run as part of
this stage. The build script links and inspects the binary but does not
execute it. Check compatibility and perform security validation before
shipping to end users.

The archive includes `build.json`, `mozilla-runtime.json`,
`neqo-provenance.json`, `rust-dependencies.json`, third-party notices,
Go/Mozilla/Rust licenses, and per-asset SHA-256 in build.json.
A hash stored *inside* an archive does not authenticate the artifact;
obtain it from a trusted repository/CI run.

## Stage 3: Firefox 158 initial HTTP/2 SETTINGS (opt-in)

The NSS/H2 firefox-158 profile now validates Go's actual initial client
preface and SETTINGS, then transmits the measured Firefox order:
HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=131072,
MAX_FRAME_SIZE=16384. The Go-only SETTINGS_MAX_HEADER_LIST_SIZE advertisement
is omitted; the independent Go response-header limit remains enforced.

HPACK encoder-table maximum is set to 65536 alongside the decoder-table
maximum, subject to peer SETTINGS. Strict concurrent stream admission avoids
opening extra connections simply to exceed a server stream limit.
The standard Go HTTP/2 implementation still generates and processes all
other frames, HPACK, outgoing header ordering and lifecycle. Those attributes
have not been shown to match the Firefox browser.

The network-only Neqo H3-to-H2 fallback now uses the same firefox-158 NSS
client and HTTP/2 receive profiles as direct Mozilla H2. The fallback policy
is unchanged: only before creating a request after QUIC network failure.

A pinned Go/x/net change that alters the initial SETTINGS causes a clear
error instead of a silent profile mismatch. This is a measured profile
adaptation, not an independent full HTTP/2 stack, Necko, or complete Firefox
fingerprint. These changes were neither compiled nor tested at this stage.

## Stage 4: Neqo connection lifecycle and graceful GOAWAY

The Linux amd64 Neqo HTTP/3 client maintains a bounded pool of **at most
eight simultaneously live QUIC engines**, including engines draining after
GOAWAY or being evicted. A connection is reused only when its TLS identity
policy matches, it remains healthy and it is not draining. Idle pool entries
are retired after 75 seconds (before the current 90-second Neqo QUIC idle
timeout), while active request bodies are not interrupted by idle expiry.

A received HTTP/3 GOAWAY now retires the affected connection instead of
treating it as a fatal protocol error: existing streams may finish naturally;
new requests use a fresh Neqo connection with certificate verification.
When no native slot is available, an idle connection can be retired and
joined before replacing it. If every slot has active work, new requests
receive a capacity error rather than exceeding the native-memory budget.

The only automatically retried request is one rejected locally as
"draining" **before Neqo created any HTTP/3 stream**; this is bounded
to one retry and the request body has not been read. Network errors,
TLS/ALPN trust failures, HTTP errors, and closed streams after request
creation never cause automatic replay or a security downgrade.

QUIC transport parameters, congestion control, resumption/0-RTT policy
and the Rust C ABI remain unchanged at this stage. The result uses Mozilla
Neqo but is not proven to match Firefox's QUIC or HTTP/3 fingerprint.
It does not implement network-address migration, ECH or HTTP/3 datagrams.

Stage 4 changes have not been compiled or tested yet, per the current
no-tests development instruction. Native memory, packet timing, and
real-network loss/recovery need subsequent independent validation.
