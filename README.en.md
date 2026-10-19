# FoxTunnel

[Русский](README.md) · **English** · [Documentation](docs/README.en.md) · [MIT](LICENSE)

FoxTunnel is an **experimental** client–server TCP tunnel: a local SOCKS5 proxy, an HTTPS server and several built-in transports. No Xray process or external proxy sidecar is required.

> **Status:** research prototype, not a general-purpose VPN. Only an opt-in experimental UDP request/response relay is present (SOCKS5 UDP ASSOCIATE); full UDP, TUN, route management and a kill switch are not implemented. Firefox fingerprint equivalence and resistance to network filtering have not been demonstrated.

## Implemented features

| Area | Current implementation |
|---|---|
| Client | Local SOCKS5 for TCP and experimental UDP; CA/SNI certificate validation and optional SPKI pin |
| Server | HTTPS, TCP forwarding and experimental UDP relay, authentication, destination controls and an optional static public site |
| Transports | `h2-connect`, `h2-post`, `h3-post`, `wss`, `xhttp-stream-one`, `xhttp-stream-up`, `xhttp-packet-up` |
| TCP TLS | Go TLS; Mozilla NSS is the default in supported `-tags nss` Linux builds |
| HTTP/3 | `quic-go` by default; a **separate opt-in Mozilla Neqo experiment** on Linux amd64 |
| Other | Cluster ingress nodes, bounded bond lanes, managed users/quotas and a Go SDK |

NSS does not implement the entire Firefox stack; Neqo does not import Necko or guarantee Firefox-like network behavior. The HTTP/2 and server implementation still uses Go.

## Build and quick start

Requires **Go 1.26+** (CI pins 1.26.9). From the repository root:

```sh
go test ./...
go build -o foxtunnel ./cmd/foxtunnel
./foxtunnel version --json
```

Configure DNS and bring your **own valid TLS certificate and private key**. FoxTunnel does not issue certificates or configure the firewall.

```sh
./foxtunnel setup --server https://proxy.example \
  --cert /etc/ssl/proxy/fullchain.pem \
  --key /etc/ssl/proxy/key.pem \
  --out server-config
./foxtunnel server --config server-config/server.json
```

Transfer `server-config/connection.txt` securely to the client machine:

```sh
./foxtunnel client --link-file connection.txt
```

**Connection links contain credentials.** Never publish them in source control, URLs or logs. For private CAs, cluster ingress and detailed setup, follow the [setup guide](docs/guides/SETUP.en.md).

## Builds and backend selection

**Public release archives**, when available, target Linux amd64/arm64 with NSS. A CI workflow does not itself imply that a release exists. See [distribution and verification](docs/reference/DISTRIBUTION.en.md).

The **Mozilla Neqo** H3 client is an **opt-in experiment built separately** on Linux amd64 with CA/SNI/SPKI verification before HTTP credentials and 0-RTT disabled. It is not in normal release archives. Follow [Neqo build and trust documentation](docs/research/NEQO-INTEGRATION.en.md). The older `experiments/neqo-ffi` probe is not a usable H3 client.

`auto` selects NSS for supported TCP transports in tagged Linux binaries and `quic-go` for H3. Explicitly unsupported backends fail rather than silently downgrading.

## Documentation

- [Setup](docs/guides/SETUP.en.md) · [Connection links](docs/guides/CONNECTION-LINKS.en.md) · [Endpoints](docs/guides/ENDPOINTS.en.md)
- [Architecture](docs/architecture/ARCHITECTURE.en.md) · [Transports](docs/architecture/NATIVE-TRANSPORTS.en.md) · [XHTTP](docs/architecture/XHTTP.en.md) · [Bonding](docs/architecture/BONDING.en.md)
- [Security](docs/reference/SECURITY.en.md) · [Access and quotas](docs/reference/ACCESS.en.md) · [SDK](docs/reference/SDK.en.md) · [Wire draft](docs/reference/WIRE-DRAFT-0.md)
- [Research](docs/research/README.en.md) · [Measurements](docs/measurements/README.en.md) · [Roadmap](docs/planning/ROADMAP.en.md)

**Full documentation map and historical notes:** [docs/README.en.md](docs/README.en.md).

## Validate and assess limitations

```sh
go test -race ./...
go vet ./...
python3 scripts/check_docs_links.py
```

Loopback experiments do not establish operator-network effectiveness. Read the [security model](docs/reference/SECURITY.en.md), [compatibility policy](docs/reference/COMPATIBILITY.en.md) and [distribution rules](docs/reference/DISTRIBUTION.en.md) before deployment.
