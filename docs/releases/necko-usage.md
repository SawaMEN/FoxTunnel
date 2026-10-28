## Unified Mozilla Linux release (branch xfd)

Linux amd64: download a single `vetroffproxy_VERSION_linux_amd64.tar.gz` archive.
It contains one NSS-enabled VetroffProxy CLI, the full verified Necko runtime,
a private managed helper, NSS libraries, source patches and licenses.
Extract the whole directory; do not move the executable without `lib/` and `runtime/`.

```sh
tar -xzf vetroffproxy_VERSION_linux_amd64.tar.gz
export FOXTUNNEL_USER='your-user'
export FOXTUNNEL_PASSWORD='your-password'
./foxtunnel-necko/vetroffproxy client --engine auto --transport h3-connect \
  --server https://proxy.example.com --listen 127.0.0.1:1080
```

The combined bundle selects full Necko for compatible H2/H3 CONNECT, and uses
NSS/Go for modes Necko cannot implement. Force `--engine necko` to reject
unsupported features instead of automatically selecting another engine.
Run `./foxtunnel-necko/vetroffproxy version --json` to inspect compiled backends.
Go SDK consumers can use `Engine: "auto"` and `NeckoBundle` pointing to the
extracted directory. Empty Engine in the SDK preserves legacy behavior.

Linux arm64: one `vetroffproxy_VERSION_linux_arm64_nss.tar.gz` archive with NSS,
without full Necko support. Both archives require signature/provenance verification
against the published release and tested source commit.
Full Necko remains experimental, supports TCP H2/H3 CONNECT only, and has not
been demonstrated indistinguishable from Firefox or reliable on arbitrary networks.
