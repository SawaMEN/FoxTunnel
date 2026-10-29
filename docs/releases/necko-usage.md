## VetroffProxy: Linux installation

Linux amd64: download a single `vetroff_VERSION_linux_amd64.tar.gz` archive.
It contains one NSS-enabled VetroffProxy CLI, the full verified Necko runtime,
a private managed helper, NSS libraries, source patches and licenses.
Extract the whole directory; do not move the executable without `lib/` and `runtime/`.

```sh
tar -xzf vetroff_VERSION_linux_amd64.tar.gz
export VETROFF_USER='your-user'
export VETROFF_PASSWORD='your-password'
./vetroff-necko/vetroff client --engine auto --transport h3-connect \
  --server https://proxy.example.com --listen 127.0.0.1:1080
```

The combined bundle selects full Necko for compatible H2/H3 CONNECT, and uses
NSS/Go for modes Necko cannot implement. Force `--engine necko` to reject
unsupported features instead of automatically selecting another engine.
Run `./vetroff-necko/vetroff version --json` to inspect compiled backends.
Go SDK consumers can use `Engine: "auto"` and `NeckoBundle` pointing to the
extracted directory. Empty Engine in the SDK preserves builtin behavior.

Linux arm64: one `vetroff_VERSION_linux_arm64.tar.gz` archive with NSS and the
complete Necko runtime, matching the AMD64 distribution. Both archives require signature/provenance verification
against the published release and tested source commit.
Full Necko remains experimental, supports TCP H2/H3 CONNECT only, and has not
been demonstrated indistinguishable from Firefox or reliable on arbitrary networks.
