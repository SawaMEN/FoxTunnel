
## Full Mozilla Necko engine (Linux amd64)

The `_necko.tar.gz` archive includes the main CLI, verified native Firefox
runtime, standalone helper, source patches and dependency notices. Extract the
whole archive and keep its files together. `--engine necko` starts and stops the
native runtime automatically; its TLS, HTTP/2 and HTTP/3 use Mozilla's stack.

```sh
export FOXTUNNEL_USER='your-user'
export FOXTUNNEL_PASSWORD='your-password'
./foxtunnel-necko/foxtunnel client --engine necko --transport h3-connect \
  --server https://proxy.example.com --listen 127.0.0.1:1080
```

Use `h2-connect` for HTTP/2. Go SDK users set `Engine: "necko"` and
`NeckoBundle` to the extracted directory. This release gates actual CLI/SDK
H2/H3 transfer, authenticated local IPC, trust, half-close, shutdown, Firefox
self-comparisons and five-minute native churn per protocol.

Verify `NECKO_SHA256SUMS` and GitHub artifact attestations before installation.
The `_nss.tar.gz` archives support Linux amd64 and arm64 with the separate NSS
backend; they do not include the full Necko runtime. Necko currently supports
Linux amd64 TCP CONNECT only. UDP, padding, Bond, fallback and manual network
profile overrides are rejected. This is an experimental prerelease; the
controlled tests do not establish DPI indistinguishability or production VPN
reliability.
