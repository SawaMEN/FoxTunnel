# NSS ClientHello capture

[Development](../../docs/DEVELOPMENT.md)

A local C probe that sends a TLS 1.3 ClientHello with h2/http1.1 ALPN to
`127.0.0.1`. The recorder closes before a full handshake. This is a measurement
tool, not the runtime TLS adapter or a Firefox fingerprint.

Build from the repository root on Debian/Ubuntu:

```sh
sudo apt-get install libnss3-dev libnspr4-dev pkg-config
cc -std=c11 -Wall -Wextra -Werror -O2 \
  $(pkg-config --cflags nss nspr) experiments/nss-clienthello/main.c \
  -o nss-clienthello $(pkg-config --libs nss nspr)
```

Start the recorder:

```sh
go run ./cmd/ft-fingerprint --listen 127.0.0.1:19443 --out nss.json
```

In another terminal:

```sh
./nss-clienthello 19443 example.org
```

Inspect the captured JSON and record `pkg-config --modversion nss nspr`.
The system NSS version can differ from Firefox's bundled version.
