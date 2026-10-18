# vetroff:// connection links

[Русский](CONNECTION-LINKS.md) | **English**

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

TLS: go/nss. Balance: failover/round-robin/least-active. Pipeline: auto/4/8.
Bonding requires two nodes and cannot combine with padding. NSS requires the
appropriate local build and never silently substitutes Go TLS.

Limits: 16-KiB URI, 256-byte username, 1024-byte password, eight unique HTTPS
origins without embedded credentials or non-root paths. Positive setup/attempt
timeouts are capped at two minutes/30 seconds; bonding attempts require at least
100ms. Defaults are 15s/5s. Unknown fields/versions, duplicate or case-variant
keys and trailing JSON objects fail. No filesystem paths, server flags,
verification bypasses or commands are accepted.

Tests cover multiple nodes, IPv6, Unicode credentials, special characters,
ambiguous JSON, bounds, redacted errors and decoder fuzzing. CLI generation and
stdin import were checked by starting a loopback SOCKS listener.
