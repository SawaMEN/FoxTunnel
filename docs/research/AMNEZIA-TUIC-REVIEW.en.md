# Amnezia, AmneziaWG and TUIC v5: source review

[Русский](AMNEZIA-TUIC-REVIEW.md) | **English**

Reviewed October 18, 2026: selected sources/specification, without running
external implementations, exhaustive dependency audit or Russian network tests.
Full pinned links are in the [Russian report](AMNEZIA-TUIC-REVIEW.md).

| Component | Snapshot |
| --- | --- |
| AWG Go | v3.1.20260828, b5928efb6ca19f0153958460c3d141f04abc5c2e; observed master/latest v3.x tag |
| Amnezia Client | ffba1cb2a4286c2cd15c8f16d20a780d857a027e, October 17; branch head, not an application release claim |
| TUIC v5 specification | 8e118f242f24a17a9f487dc344cc50d7e63e557e; version 0x05 |
| Itsusinn/tuic | 26e28e9c9e3b5bddfa06fa0b5611638527687775, October 10; selected implementation |
| Its pinned wind-tuic dependency | 12fbf7a690a4f20be6c9c593addf42a670cfc1a5; inspected checkout matches Cargo rev |

Application version, AWG generation and backend tag are distinct. The TUIC
specification repository has no single official implementation. Wind's actual
authentication path was inspected alongside the application configuration layer.

## Amnezia

Reviewed AWG README, receive/noise/timers and Amnezia's AWG configurator/exporter.
AWG 3 separates header protection/padding/timing from its WireGuard foundation.
Receive-side MAC/cookie/rate admission under load is useful; disabling cookies
alters that defense. Amnezia produces matching profiles and separates client
export from administrative SSH credentials. Adopt generated strong secrets,
complete client profiles and separate private server configuration.

AWG is a UDP/TUN transport without mandatory TLS SNI. Adding its framing before
NSS would not produce Firefox TLS. AWG framing/crypto was not copied or replaced;
random timing/junk packets were not added to HTTPS.

## TUIC v5

Useful QUIC streams/datagrams, explicit UDP associations and TLS-exporter-bound
authentication. The pinned Wind implementation waits for TLS completion,
allows one Authenticate attempt per connection, compares without early exit
and avoids separate unknown-user/bad-token errors. The application atomically
reserves per-user connection limits. Its client has optional insecure certificate
verification and configurable 0-RTT, off by default. FoxTunnel adds neither
insecure verification nor early data.

The base specification has no standard Connect/error response; implementation
policy matters. FoxTunnel retains explicit opening results/ACKs. Exporter-bound
authentication requires a negotiated protocol, NSS support and a plan for
TLS-terminating HTTP frontends; it was not implemented. Basic inside TLS is not
the same mechanism. H3/UDP remain future transports; QUIC alone is not browser
fingerprint parity and needs another carrier when UDP is blocked.

## Delivered independently

SNI/SPKI/tls13 link fields, per-ingress policies, additive CA/name/pin checks in
Go/NSS, isolated identity pools/ticket caches, setup/join/registration/config-file
commands, pre-handshake socket limits and public-site confinement. No external
protocol source was copied. See [security matrix](../reference/SECURITY.en.md) and [setup](../guides/SETUP.en.md).
