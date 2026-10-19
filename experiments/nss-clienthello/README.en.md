# Mozilla NSS ClientHello experiment

[Русский](README.md) · **English** · [Documentation](../../docs/README.en.md)

> **Scope:** Standalone NSS ClientHello probe for controlled fingerprint experiments.

This is a **capture-only**, standalone C program linked against Mozilla NSS/NSPR.
It connects **only to `127.0.0.1`**, emits an NSS ClientHello (TLS 1.3,
`h2`/`http/1.1` ALPN, configurable SNI) and expects the capture listener to
terminate the connection without completing a TLS handshake.

**This is not FoxTunnel's TLS transport and is not the full Firefox fingerprint.**
There is no HTTP/2 implementation here, no connection to remote services, and
no certificate accepted or validated. A future production transport MUST verify
certificate chains and hostnames with a properly configured NSS trust store and
must not inherit the intentional early termination behavior of this tool.

## Build on Debian/Ubuntu

```sh
sudo apt-get install libnss3-dev libnspr4-dev pkg-config
cc -std=c11 -Wall -Wextra -Werror -O2 \
  $(pkg-config --cflags nss nspr) experiments/nss-clienthello/main.c \
  -o nss-clienthello $(pkg-config --libs nss nspr)
```

## Capture

Terminal 1:

```sh
go run ./cmd/ft-fingerprint --listen 127.0.0.1:19443 --out nss.json
```

Terminal 2:

```sh
./nss-clienthello 19443 example.org
```

The NSS program reports an attempted handshake; the capture JSON is evidence
that a ClientHello was actually received and parsed. Compare the NSS output
with `ft-fingerprint --sample-go` or a real Firefox capture, always recording
the library and browser versions. NSS does not include the entire Firefox Necko
stack or automatically reproduce its ClientHello ordering/settings.

The current research experiment uses system NSS at build/runtime. A production
implementation must pin an audited NSS/NSPR version, manage CVE updates, and
support Windows/macOS/Linux lifecycle requirements separately.
