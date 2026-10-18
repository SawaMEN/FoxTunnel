# Simple main-node and ingress preparation

[Русский](SETUP.md) | **English**

`setup` generates a random 256-bit access secret, server configuration, public
node descriptor and a `vetroff://` link carrying SNI, TLS 1.3 and an SPKI pin.
Secrets are not printed. New directories/files use 0700/0600; existing output
directories are never overwritten. Supply a valid certificate and matching
private key. Chain/name/expiry are checked, with at least 24 hours remaining.
Certificate issuance/renewal, DNS, software installation and firewall changes
are not automated by this CLI.

## Main node

```sh
./foxtunnel setup --server https://main.example \
  --cert /etc/certs/main/fullchain.pem --key /etc/certs/main/key.pem \
  --web-root /srv/public-site --out main-node
./foxtunnel server --config main-node/server.json
```

No credential environment variables are required. The main node initially
lists itself as a direct ingress. Share only `main-node/connection.txt`:

```sh
./foxtunnel client --link-file connection.txt
```

The link contains an access secret; base64url is not encryption. Server JSON
and the private TLS key remain administrative files. Setup selects Go TLS;
`setup --tls-backend nss` generates a profile requiring an NSS-capable client.
Ingress joins preserve the main-node client profile. Imported links exclude
TLS-backend overrides.

## Ingress and registration

```sh
./foxtunnel setup --server https://node-a.example \
  --cert /etc/certs/node-a/fullchain.pem --key /etc/certs/node-a/key.pem \
  --join-link-file main-connection.txt --out node-a
./foxtunnel server --config node-a/server.json
```

The ingress imports cluster credentials and main-node SNI/pin. Its connection
file still points users at the main node. Transfer public `node-a/node.json`
to the main administrator and register it there:

```sh
./foxtunnel cluster-add --config main-node/server.json --node-file node-a.json
```

This validates configuration and atomically updates topology on Linux, without
restarting or replacing links. The same URL is updated idempotently. An exclusive
lock prevents concurrent updates; after a crash, remove a stale `.lock` only
after verifying no writer is running. Registration performs no availability
probe. Clients measure paths on demand. Up to eight entries include the direct
main path and disabled entries. Weights start at 1 and remain administrative;
automatic fleet-wide capacity estimates are not implemented. Drain old sessions
before stopping removed nodes.

## Identity, trust and changes

For an IP endpoint, add `--sni main.example`, matching the certificate. Arbitrary
unrelated names fail verification. SNI is not secret; ECH is not implemented.
DNS URLs use their hostname automatically. GET/POST authority follows explicit
SNI; CONNECT retains its target authority. Every ingress has independent SNI/pin.

Private CAs require `setup --ca-cert`, local `client --ca-cert` and, for a
private main CA, ingress setup `--bond-ca-cert`. Links inject neither CA paths
nor trust roots. Pins supplement CA verification. Use a PEM containing all
necessary roots for different private ingress CAs.

Edit `server.json` and restart to change listening address, credentials or
limits; it excludes simultaneous server-setting flags. Defaults: server :443,
512 accepted sockets and 256 authenticated handlers; client 256 SOCKS sockets,
including incomplete handshakes. Client admission has local `--max-connections`.

Certificate renewal with the same public key preserves the pin. Main key
rotation requires a new trusted link; ingress key rotation requires updated
public node metadata. Pin mismatch never silently bypasses verification.
Servers load certificates at startup and need a restart after renewal.
Public site roots must exclude private configuration/keys; outward symlinks
are rejected. See [security limits](SECURITY.en.md) and [cluster](CLUSTER.en.md).
