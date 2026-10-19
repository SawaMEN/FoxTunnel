# Unified Mozilla Transport Engine — Stage 1

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
