# vetroff:// connection links

[Русский](CONNECTION-LINKS.md) | **English**

`setup` generates complete server configuration and a link: [instructions](SETUP.en.md).
Additional settings are --sni, --pin-sha256 and --encryption tls13, serialized
as sni/pin_sha256/encryption. Pins supplement CA/name verification. These apply
to the primary origin/coordinator; ingresses have independent manifest policies.
No private server key is exported. Old links use safe defaults; older clients
reject unknown new fields. See [security properties](../reference/SECURITY.en.md).

The connection scheme is **vetroff://**. One link stores one HTTPS server or up
to eight trusted nodes, credentials and client settings. CLI import/export is
implemented; OS-level URL-handler registration is not yet implemented.

Set `FOXTUNNEL_USER` and `FOXTUNNEL_PASSWORD`, then export without opening sockets:

```sh
./foxtunnel share --server https://node-a.example
umask 077
./foxtunnel share --server https://node-a.example \
  --fallback-server https://node-b.example --bond \
  --bond-pipeline auto > connection.txt
```

Links contain the password. Base64url is encoding, not encryption; treat a link
as a secret. The example's umask restricts the generated file. Local CA paths,
SOCKS listening address and interface language are not exported.

Import without credential environment variables:

```sh
./foxtunnel client --link-file connection.txt
./foxtunnel client --link-file - < connection.txt
```

`--link 'vetroff://...'` also works, but file/stdin avoids exposing secrets in
process arguments. Successful import does not log link contents; decode errors
do not include the URI, JSON or credentials. Imported credentials replace the
environment. Link settings cannot be mixed with explicit connection-setting flags;
local `--listen`, `--ca-cert` and `--lang` remain available. A private CA must be
configured locally; a link cannot disable TLS verification.

Version 1 is `vetroff://` followed by unpadded base64url UTF-8 JSON. No path,
query, fragment or userinfo. Stable fields:

```json
{"v":1,"servers":["https://node-a.example","https://node-b.example"],"username":"example-user","password":"example-only-password","tls":"go","balance":"failover","bond":true,"pipeline":"auto","padding":false,"connect_timeout":"15s","attempt_timeout":"5s"}
```

TLS: auto/go/nss (auto uses NSS for TCP when compiled in, Go QUIC for H3). Balance: failover/round-robin/least-active. Pipeline: auto/4/8.
Explicit-node bonding requires two nodes and cannot combine with padding. Explicit NSS requires the
appropriate local build and never silently substitutes Go TLS.

`"discover":true` with `"bond":true` requires exactly one server, the coordinator.
Generate it with `share --server https://main.example --bond --discover`.
The coordinator issues ingress origins/weights; one active ingress is allowed
as degraded mode. See [cluster setup](../architecture/CLUSTER.en.md). Discovery cannot be combined
with explicit fallback servers; older clients reject the new field.

Limits: 16-KiB URI, 256-byte username, 1024-byte password, eight unique HTTPS
origins without embedded credentials or non-root paths. Positive setup/attempt
timeouts are capped at two minutes/30 seconds; bonding attempts require at least
100ms. Defaults are 15s/5s. Unknown fields/versions, duplicate or case-variant
keys and trailing JSON objects fail. No filesystem paths, server flags,
verification bypasses or commands are accepted.

Tests cover multiple nodes, IPv6, Unicode credentials, special characters,
ambiguous JSON, bounds, redacted errors and decoder fuzzing. CLI generation and
stdin import were checked by starting a loopback SOCKS listener.

## Native transport

`transport` is `h2-connect` (default), `h2-post`, `wss` or `h3-post`.
Use `share --transport wss` or `setup --transport wss`. NSS supports the first
three; `h3-post` with explicit `tls:nss` is rejected; `tls:auto` uses Go QUIC. Profiles launch no external programs.
Old links retain H2 CONNECT. See [configuration and limits](../architecture/NATIVE-TRANSPORTS.en.md).

Fields `xhttp_path` / `xhttp_host` select a shared XHTTP cluster route independently of TLS SNI/pin; other transports reject them. See [XHTTP settings](../architecture/XHTTP.en.md).
