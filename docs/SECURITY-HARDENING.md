# FoxTunnel security hardening (opt-in, no wire crypto changes)

This patch preserves **TLS 1.3**, the ordinary certificate chain and
hostname checks, HTTP/2 and HTTP/3, and Bonding's authenticated common
hub. It does not add its own encryption algorithm, disable TLS identity
checks, claim to be indistinguishable from Firefox, or provide universal
end-to-end encryption beyond the exit node.

## 1. Handle vetroff:// links as credentials, not ciphertext

The `vetroff://` URI is **Base64 URL-encoded JSON containing the
proxy username and password**. Whoever obtains it may connect with the
embedded credentials. Old links are unchanged, but owner-only file
handling is now available:

```sh
umask 077
# Credentials are set in FOXTUNNEL_USER and FOXTUNNEL_PASSWORD.
foxtunnel share --server https://node.example --out ./connection.link
foxtunnel client --link-file ./connection.link
```

`share --out` creates a fresh, regular file mode `0600`; existing
files are never overwritten and the link is not printed to stdout.
`client --link-file PATH` refuses symlinks and on Unix rejects any
group/world-readable regular file. A pipe may still be used with
`--link-file -`, or an explicit `--link` for legacy compatibility.
Do **not** send links through logs, shell history, chat history,
tickets, screenshots, QR screenshots or public issue reports.
Rotate server-side credentials if a link leaked. No claim is made
that local filesystem permissions protect against malware with the
same account's privileges.

## 2. Optional *local* SOCKS5 password (RFC 1929)

The remote proxy credentials and the local SOCKS5 password are
separate. By default, SOCKS5 continues to support no-auth on
`127.0.0.1:1080` for backward compatibility. To force SOCKS5
username/password verification on the local listener:

```sh
export FOXTUNNEL_SOCKS_USER='local-user'
export FOXTUNNEL_SOCKS_PASSWORD='choose-an-independent-secret'
foxtunnel client --link-file ./connection.link --listen 127.0.0.1:1080
```

When both variables are set, **no-auth fallback is rejected**.
The same local handshake protects SOCKS5 TCP CONNECT and UDP
ASSOCIATE. Partial/oversized credential pairs fail at startup;
server-side comparisons use fixed-size constant-time digests.
The experimental native Linux `--tun` integration currently creates
an internal no-auth SOCKS connector and therefore **rejects** this
optional local credential mode, rather than silently failing to
authenticate.

Non-loopback SOCKS5 listeners require both sets of local credentials
AND `--socks-allow-lan`:

```sh
foxtunnel client --link-file ./connection.link \
  --listen 192.0.2.10:1080 --socks-allow-lan
```

**WARNING:** RFC 1929 transmits the local SOCKS credentials in
cleartext on the client-to-local-SOCKS connection, even though
FoxTunnel→VDS runs TLS 1.3. Never use it directly over an untrusted
LAN/Internet. Prefer loopback or place an independent authenticated
encrypted tunnel/firewall in front. IPs above are illustrative.

## 3. Independent verified SPKI pins for explicit HTTPS ingress nodes

Normal CA and hostname verification **remain mandatory**. For an
explicit 2–8 node setup (including Bonding or UDP multi-node), pin
each ingress TLS public key separately. Protect the file as a trust
configuration, and list **all** configured origins once:

```json
{
  "v": 1,
  "nodes": [
    {
      "url": "https://node-a.example",
      "pin_sha256": "sha256/REPLACE_WITH_BASE64_SHA256_OF_A_PUBLIC_KEY"
    },
    {
      "url": "https://node-b.example",
      "sni": "node-b.example",
      "pin_sha256": "sha256/REPLACE_WITH_BASE64_SHA256_OF_B_PUBLIC_KEY"
    }
  ]
}
```

```sh
chmod 600 ./node-pins.json
foxtunnel client --server https://node-a.example \
  --fallback-server https://node-b.example \
  --node-pins-file ./node-pins.json
```

The placeholders are not valid pins: replace them with verified
values obtained out of band from **each node's actual certificate**.
For a trusted local PEM certificate, the SPKI pin can be calculated:

```sh
printf 'sha256/'
openssl x509 -in node-cert.pem -pubkey -noout |
  openssl pkey -pubin -outform DER |
  openssl dgst -sha256 -binary | openssl base64 -A
printf '\\n'
```

A missing, duplicated or extra origin, malformed pin, symlink, weak
file permissions or inconsistent identity fails closed. Pins are
retained across TLS backend/profile reconfiguration. This option is
for **explicit trusted** nodes only: it cannot be combined with
`--discover` or with an unrelated `--sni/--pin-sha256` primary
override. With dynamic discovery, continue to use the coordinator
and manifest's existing per-node TLS identities. Rotate the pinned
file and restart clients when certificates/keys rotate. A pin is
an **additional** key match, not a substitute for CA verification.

## 4. DPI and fingerprint measurements: evidence only

Historical audit tools already compare observed Firefox and FoxTunnel
TLS ClientHello, ALPN, H2 SETTINGS and, when measured, QUIC/H3
transport metadata. Run them alongside the security regression tests:

```sh
python3 -m unittest discover -s scripts -p 'test_fingerprint_audit.py' -v
python3 scripts/fingerprint_audit.py \
  --firefox docs/measurements/2026-10-18/firefox-158-linux.json \
  --foxtunnel docs/measurements/2026-10-19/nss-firefox158-page.json \
  --out ./private-fingerprint-audit.json
```

These measurements are historical and **do not** establish current
DPI performance. A real deployment should independently measure TLS
extensions/order, ALPN, H2 framing, QUIC handshake sizes, packet
timing and traffic shape, and compare against native Firefox on the
*same network and scenario*. Padding cannot hide server IP and all
traffic timing. Strong TLS ciphertext does not make the traffic
undetectable; do not claim parity without compatible captures.

## 5. Security review and remaining risks

Automated tests cover malformed/private link files, failed password
negotiation, local UDP/TCP command authentication, SPKI mismatches,
verified HTTPS transport, multi-node fail-closed routing, and the
existing fingerprint audit's non-inference rules. They are **not**
an independent penetration test or cryptographic proof.

Remaining deployment obligations:

- Individual node/account credential scopes: currently the same
  proxy credentials may be presented to multiple explicitly trusted
  nodes. Separate per-node credentials and managed rotation would
  require a new protocol/profile migration and have **not** been built.
- Revocation: a copied `vetroff://` link is a bearer-style secret.
  Rotate/revoke the corresponding server access when compromised.
- Public SOCKS: authentication does not encrypt the client-to-SOCKS hop.
- Exit privacy: the FoxTunnel exit sees transport plaintext; any
  application-layer HTTPS protection is independent.
- TLS libraries and NSS/Neqo native builds need updates, dependency
  tracking and periodic external review.
- WAN failure testing, traffic fingerprinting in real networks and
  an independent security review are required before declaring
  this security-hardened configuration production-ready.
