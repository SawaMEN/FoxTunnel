# Getting started

[Home](../README.en.md) · [Русский](START.md)

This guide sets up a **basic TCP SOCKS5 tunnel** first. You do not need UDP, TUN, clustering or Mozilla mode to get started.

## 1. Prerequisites

- A Linux server with its own DNS name, reachable on **TCP port 443**.
- A valid TLS certificate and corresponding private key for that name.
- FoxTunnel on the server and client.

FoxTunnel does **not** obtain certificates, configure DNS or change firewalls. Manage those separately.

## 2. Install

Use an archive for your platform from [Releases](https://github.com/SawaMEN/FoxTunnel/releases) and verify its checksum/metadata, or build from source with Go 1.26+:

~~~bash
go build -o foxtunnel ./cmd/foxtunnel
./foxtunnel version --json
~~~

Keep all bundled `lib/` files alongside the executable. A basic Go build does **not** include NSS or Neqo; Mozilla mode requires a compatible native bundle.

## 3. Start your server

Replace the placeholder domain and certificate paths with your own:

~~~bash
./foxtunnel setup \
  --server https://vpn.example.com \
  --cert /etc/ssl/foxtunnel/fullchain.pem \
  --key /etc/ssl/foxtunnel/privkey.pem \
  --out server-config

./foxtunnel check-config --config server-config/server.json
./foxtunnel server --config server-config/server.json
~~~

`setup` generates `server.json` (private server configuration), `connection.txt` (**client credentials**), and `node.json` (optional cluster metadata). Do not publish these files or share the server's TLS private key with clients. Set up a service manager if you need persistent operation.

## 4. Start your client

Securely transfer **only** `connection.txt` to the client:

~~~bash
./foxtunnel check-config --link-file connection.txt
./foxtunnel client --link-file connection.txt
~~~

Configure your application to use SOCKS5 at `127.0.0.1:1080`, with no additional local SOCKS authentication. This affects **configured applications**, not every connection made by the OS.

A simple test with curl:

~~~bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
~~~

The hostname is resolved through the proxy for this request. It is not a device-wide DNS leak test.

## Troubleshooting

| Problem | Check |
|---|---|
| TLS certificate error | DNS name, expiry, chain, CA trust and verified SNI |
| Connection refused | DNS, TCP port 443, firewall and server process |
| Authentication error | Correct current `connection.txt` and credentials |
| SOCKS works but application fails | Per-application proxy settings, DNS and destination restrictions |
| HTTP/3 fails | UDP path and compatible transport; try basic H2 first |
| Mozilla mode unavailable | Use a binary that includes native NSS/Neqo |
| Other apps bypass the tunnel | Expected without proxy configuration or separately configured TUN |

## Optional experimental modes

A compatible Mozilla Linux amd64 bundle supports:

~~~bash
./foxtunnel client --engine mozilla --link-file connection.txt
~~~

The [v0.1.0-alpha.2](https://github.com/SawaMEN/FoxTunnel/releases/tag/v0.1.0-alpha.2) experimental bundle predates the most recent `main` merge. The connection file's transport is preserved.

UDP ASSOCIATE requires `--enable-udp` on server and client; opt-in persistent UDP also requires the client's `--udp-stream`. The host VPN client owns TUN, routing, firewall and DNS; the built-in TUN has been removed. See the [integration contract](INTEGRATION.md).

See [Features and configuration](FEATURES.en.md) for details.
