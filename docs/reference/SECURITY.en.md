# Security properties and limits

[Русский](SECURITY.md) · **English** · [Docs](../README.en.md)

> **Scope:** Threat model, enforced TLS checks, limitations and uncovered use cases.

This is an implementation review, not an external audit or a claim to match
every VPN. Channel protection, detectability and full-device VPN behavior are
different properties. FoxTunnel uses standard TLS 1.3, not a custom cipher.

## Connection fields

| Field | Meaning |
| --- | --- |
| username | Access identifier, not encryption key |
| password | Access secret; setup generates 32 crypto/rand bytes |
| sni | Verified DNS certificate name, defaulting to the URL hostname |
| pin_sha256 | Optional additional sha256/base64 SPKI pin, computed by setup |
| encryption | Only tls13; safe TLS cipher negotiation |
| tls | go/nss implementation, not cipher name |
| bond/discover | Path bonding and main-node topology discovery |

No server private key or ephemeral session key is exported. An SPKI hash is
public verification data. Base64url links contain an access secret and require
a trusted delivery channel; they are neither encrypted nor signed. Links cannot
disable verification, import local paths or run commands. Local CAs are added
separately. Old links default to TLS 1.3/URL hostname; old clients reject new fields.

## Implemented protections

Verified TLS 1.3 and h2 precede HTTP credentials on every hop. Ephemeral key
exchange protects past sessions; the access secret is not the traffic encryption
key. See [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html). CA chain,
hostname and optional pin are all required. Pins supplement trust rather than bypassing
it. Per-origin/SNI/pin pools and Go ticket caches isolate identities. NSS now
honors VerifyConnection after x509 validation, rejects insecure verification,
and retains disabled session resumption. Invalid certificates/pins never cause
weaker-mode fallback. SNI is generally observable; ECH is not implemented.
Explicit SNI also sets GET/POST authority; CONNECT retains its target.

Basic credentials are carried inside verified TLS; fixed-length hashes are
compared in constant time. TLS record replay protection is separate from bond
sequence/ACK/deduplication and opening-token expiry. Application 0-RTT is off.
Default bounds: 256 authenticated handlers, 512 accepted server sockets including
incomplete TLS, and 256 local SOCKS sockets including incomplete handshakes.
These are resource limits, not complete distributed DoS protection.

Public sites reject directory listings, dotfiles, known private configuration/key
files and symlink escape; configured private paths cannot overlap the site root.
Generated directories/files use 0700/0600, refuse overwrites and do not print
secrets. Only public assets belong in the website directory.

Ingress nodes are trusted TLS endpoints seeing tunnel data. Application HTTPS
remains end-to-end when used; FoxTunnel is not an anonymity network or protection
against compromised trusted nodes.

## Remaining gaps

The prototype adds **opt-in** experimental UDP ASSOCIATE (one-shot HTTPS POST v1 and separately enabled multiplexed HTTP streaming v2) to SOCKS5 TCP; there is still no TUN, native QUIC DATAGRAM, network migration, OS kill switch or guarantee of
capturing all system DNS/traffic. There is no independent audit or Russian TSPU
field evidence; NSS plus Go H2 is not Firefox parity. Authentication is a bearer
credential inside TLS, without TUIC-style TLS-exporter channel binding. Per-user
keys/revocation and global cluster telemetry are absent. The main exit remains
a failure/bandwidth bottleneck. Certificate provisioning/renewal remains an operational requirement. Versioned
Linux NSS archives bundle pinned Mozilla libraries; updating them requires a new
FoxTunnel release. Developer/SDK builds use their own NSS/NSPR environment.

Go/NSS race/integration tests cover custom identity, wrong name/key/CA before
HTTP, policy isolation, bond failure/deduplication, setup/join and private output,
socket admission and public-site confinement. URI/topology fuzzing remains in CI.
Known-vulnerability scan methodology: govulncheck v1.9.0, Go 1.26.9, symbol-level
source scan, vuln.go.dev last observed updated 2026-10-08. Both default/NSS-tagged scans completed with exit 0 and no findings; both CI
jobs now run the pinned scanner. This cannot rule out unknown bugs or scan
native NSS. The shared-ticket-key regression test fails on a deliberately
weakened copy without cache isolation and passes on the delivered code.

See [setup](../guides/SETUP.en.md), [Amnezia/TUIC review](../archive/reviews/AMNEZIA-TUIC-REVIEW.en.md)
and [connection links](../guides/CONNECTION-LINKS.en.md).

## Additional native transports

H2 POST, WSS and H3 POST/QUIC retain CA/SNI/pin checks and authentication.
WSS checks credentials before Upgrade and authenticates inner H2 requests again.
WebSocket compression and QUIC 0-RTT are disabled. Messages, headers, streams,
windows and incoming connections are bounded; this does not replace an audit.
See [transport properties and limits](../architecture/NATIVE-TRANSPORTS.en.md).

After adding dependencies, govulncheck found no reachable vulnerabilities or
vulnerabilities in imported packages. It reports module-level GO-2026-5932 for
unused golang.org/x/crypto/openpgp; that package is not imported. Native NSS
libraries still require separate maintenance.
