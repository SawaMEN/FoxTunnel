[Русский](README.md) | **English**

Client identity settings now support SNI and an additive SPKI pin. VerifyConnection
runs after x509 chain/name validation; insecure verification and unsupported
VerifyPeerCertificate callbacks are rejected. See [security properties](../../docs/SECURITY.en.md).

# Experimental NSS transport (Linux)

Build with Go 1.26+, a C compiler, pkg-config, NSS and NSPR development packages:

```sh
sudo apt-get install libnss3-dev libnspr4-dev pkg-config
go build -tags nss -o foxtunnel ./cmd/foxtunnel
FOXTUNNEL_USER=alice FOXTUNNEL_PASSWORD=secret ./foxtunnel client \
  --tls-backend nss --server https://your-server.example
```

Use `--ca-cert` for a private CA without disabling verification. The existing
FoxTunnel H2 server is compatible. An ordinary build without the nss tag keeps
Go TLS and explicitly rejects `--tls-backend nss`; it never silently substitutes
a different backend. Unsupported platforms also return a clear error.

NSS handles the TLS 1.3 handshake, key exchange, encryption/decryption and h2
ALPN negotiation. A custom NSPR layer borrows Go-managed TCP I/O using opaque
cgo handles. Go's x509 verifies the complete peer-supplied chain against the
configured CA pool/system roots, hostname, validity and serverAuth usage.
The certificate hook never accepts a failed verification. No HTTP request or
proxy credentials are sent before a verified handshake and h2 negotiation.

Context cancellation closes TCP to unblock C/Go I/O callbacks. Read/write
operations are serialized independently; Close first interrupts the raw socket,
then waits for operations to unwind before destroying NSS state and deleting
the handle. NSS initializes once for process lifetime. Close currently interrupts the raw socket before destroying NSS state and does not guarantee an orderly TLS close_notify; browser-like teardown remains a measurement task. No 0-RTT is used. NSS
session caching/tickets are disabled for this first adapter so authentication
hooks cannot be skipped on resumed sessions; Go-backend session resumption
remains supported. Peer chains are bounded to 16 certificates of at most 1 MiB
each. There is no Firefox OCSP/revocation or Necko behavior parity claim.

Tests include full SOCKS/H2 payload transfer on concurrent streams, hostname
and trust rejection, required h2 ALPN, CONNECT/handshake cancellation, concurrent
close and half-close. Run:

```sh
go test -race -tags nss ./... -count=1 -timeout=60s
go vet -tags nss ./...
go test -race ./... -count=1 -timeout=60s
```

Record `pkg-config --modversion nss nspr` in measurements. Distro NSS versions
may differ substantially from current Firefox. Keep production dependencies
updated through the OS vendor and record backport versions. NSS can only change
TLS behavior: H2 remains Go x/net/http2, and no browser-equivalent profile, H3,
UDP, DNSTT or real-network TSPU test is provided by this adapter. Optional
initial-record padding belongs to the tunnel layer and supports both backends;
see [its specification](../../docs/PADDING.en.md).
