# Stage two: measured Mozilla TLS/H2 preferences

[Русский](MOZILLA-CLIENT-PROFILE.md) | **English**

Baseline: main `31001ff`, pinned Firefox 158.0 / NSS 3.130, Go 1.26.9, Linux amd64.
NSS remains the default backend; this additional profile is opt-in. Releases
remain Linux amd64/arm64 NSS only. The tunneled payload format is unchanged.

```sh
foxtunnel client --link-file connection.txt \
  --tls-client-profile firefox-158 --h2-receive-profile firefox-158
```

The local client option is not serialized into links/setup/server JSON. SDK:
`ClientConfig.TLSClientProfile = foxtunnel.TLSClientFirefox158`; configure
`HTTP2ReceiveProfile = foxtunnel.HTTP2ReceiveFirefox158` separately.
The profile uses socket-local `SSL_NamedGroupConfig`,
`SSL_SendAdditionalKeyShares` and `SSL_SignatureSchemePrefSet`, not rewritten
ClientHello bytes. It survives per-origin/SNI/pin transport creation. Other NSS
versions, Go and H3 reject it without fallback; `default` resets it. Global NSS
preferences are unchanged.

| Field | Default NSS | firefox-158 | Stored Firefox reference |
|---|---|---|---|
| supported_groups | 4588,29,23,24,25,4587,4589,256–260 | 4588,29,23,24,25 | Matches profile |
| key share groups | 4588 | 4588,29,23 | Matches profile |
| signature schemes | 14, including PSS-PSS | Same 11 values as Firefox, different order | PKCS#1 before ECDSA-SHA1 |
| versions | TLS 1.3 only | TLS 1.3 only | TLS 1.3 and 1.2 |
| H2 ALPN | h2 | h2 | h2, http/1.1 |
| ClientHello record body here | 1390 bytes | 1475 bytes | 1882 bytes in stored capture |

Groups: 4588 = X25519MLKEM768, 29 = X25519, 23 = P-256, 24 = P-384, 25 = P-521.
WSS retains the single `http/1.1` ALPN and does not support the H2 receive profile.

NSS `ssl3_FilterSigAlgs` moves PKCS#1 certificate signature schemes last when the
minimum version is TLS 1.3. The actual profile sends
`1027,1283,1539,2052,2053,2054,515,1025,1281,1537,513`; Firefox's stored capture
sends `1027,1283,1539,2052,2053,2054,1025,1281,1537,515,513`. Wire tests record the
actual result. TLS 1.2 is not advertised solely to alter this order.

## Reproduce measurements

Build with NSS headers; run using the pinned runtime in `scripts/mozilla-runtime.lock.json`.
Create an isolated fixture certificate:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -keyout fixture.key -out fixture.crt -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
go build -tags nss -o ft-webprofile ./cmd/ft-webprofile
./ft-webprofile --listen 127.0.0.1:0 --cert fixture.crt --key fixture.key \
  --sample nss --scenario page --duration 500ms \
  --tls-client-profile firefox-158 --h2-receive-profile firefox-158 \
  --source 'NSS 3.130; Go 1.26.9; Linux amd64; direct fixture HTML GET; firefox-158' \
  --out candidate.json --compare docs/measurements/2026-10-18/firefox-158-linux.json \
  --comparison-out comparison.json
```

For a baseline, use default profiles and another output file. `page` makes a
direct verified H2 GET of the same public HTML fixture served to Firefox, without
SOCKS/inner H2/echo. Explicit `--transport` is rejected for this scenario. `tunnel`
exercises the real SOCKS and selected carrier. Headers/browser lifecycle still
differ. Do not compare aggregate record counts/timings across the two workloads.

`--comparison-out` requires `--compare`. It reports individual TLS fields,
ordered SETTINGS, per-setting values and connection credit. `--strict` still
fails for differences, after saving the report. JA3/MD5 and timing are not scored;
matching all selected fields is not browser or censorship equivalence.

[Stored new captures](../measurements/2026-10-19/) contain default/profile HTML
GETs, a profile XHTTP echo and a field comparison. The reference is the
[18 October Firefox capture](WEB-PROFILE.en.md), not a new browser run on
19 October. New GETs align the workload type, but are not a synchronized browser
comparison on the same host/route. Reports contain no HTTP payload, credentials,
keys or SNI hostname.

## Connection lifecycle and cost

Tests verify reuse of one H2/TLS connection for sequential GETs and a fresh full
TLS 1.3 handshake after closing idle connections. NSS tickets/resumption/0-RTT
remain disabled. Enabling them needs a bounded origin/SNI/pin/profile cache and
mandatory trust/pin checks on resumption; metadata agreement cannot justify a
verification bypass.

A server forced to select X25519 receives two ClientHellos with default NSS
(HelloRetryRequest), but only one with the profile; both complete a verified HTTP
exchange. This confirms usable additional key shares. Servers already selecting
the first share do not gain this round trip.

Fresh TLS/H2 plus a small GET, sequential loopback, shared AMD EPYC 9V74,
Go 1.26.9/NSS 3.130/Linux amd64, three 300 ms runs:

| Profile | Exchange time | Go bytes/op | Go allocations/op |
|---|---|---|---|
| default | 2.38–2.49 ms | 87.7–89.2 KB | 686–689 |
| firefox-158 | 2.40–2.55 ms | 88.0–88.5 KB | 688–689 |

Ranges overlap; no ordinary-handshake speed advantage is established. Allocation
figures omit native NSS memory. This is not Internet throughput or a DPI test.

## Decisions and remaining work

- Preserve TLS 1.3 and the actually supported ALPN. Policy changes require real negotiation tests.
- Do not advertise OCSP/SCT/delegated credentials/compression/ECH processing that is not implemented; support and validation precede captures.
- Retain real H2 receive windows/HPACK decoder. SETTINGS order, encoding, headers, priorities and browser lifecycle still differ.
- Retain the tested Go/x/net H2 engine. Vendoring it solely to reorder SETTINGS is not justified; a Necko/adapter decision needs measured benefit and maintenance scope.
- Keep NSS resumption off pending isolated token/cache and negative CA/pin tests.
- Neqo remains a separate stage; current quic-go H3 is not Mozilla.

Tests cover actual H2/WSS ClientHello, socket isolation, TLS/ALPN rejection,
CA/SNI/pin before HTTP, large data/half-close, SDK, credit renewal, cancellation
and failed-transition rollback. Full Firefox conformance remains unfinished.
This profile is a measured configuration subset, not a replacement TLS/H2 stack.

Mozilla sources: [socket settings](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_158_0_RELEASE/security/manager/ssl/nsNSSIOLayer.cpp),
[signature preferences](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_158_0_RELEASE/security/manager/ssl/EnabledSignatureSchemes.h),
[TLS-1.3 filtering](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_158_0_RELEASE/security/nss/lib/ssl/ssl3con.c),
[NSS API](https://github.com/mozilla-firefox/firefox/blob/FIREFOX_158_0_RELEASE/security/nss/lib/ssl/ssl.h).
