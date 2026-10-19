# Comparing FoxTunnel and VLESS under the same workload

**English** | [Русский](TRANSPORT-COMPARISON.md) · [Research](README.en.md)

`scripts/compare_transports.py` is a dependency-free Python 3.11+ harness. It connects to **already running local SOCKS5** endpoints for FoxTunnel and Xray/VLESS, issues CONNECT to the **same controlled TCP echo server**, checks every returned byte and exports latency, throughput, failures and samples as JSON.

Specify which VLESS transport you mean, for example REALITY/Vision or XHTTP/TLS.

## Isolated lab setup

1. Start the echo target **on a shared egress node**: `python3 scripts/echo_server.py --host 127.0.0.1 --port 9000`. It has no authentication; do not expose it publicly. `--host LAB_IP --allow-public` is intended only for an isolated lab with a restrictive firewall.
2. Start FoxTunnel with SOCKS5 on `127.0.0.1:1080` and Xray with a separate local SOCKS5 inbound on `127.0.0.1:1081` routed through the configured VLESS outbound. Bind both SOCKS listeners to **loopback**. Match egress, DNS rules, CPU/network capacity and routes.
3. FoxTunnel blocks remote loopback/private targets by default. `server --allow-private` is appropriate **only within an isolated trusted test**, never as an incidental setting on a public proxy. An authorized dedicated echo address with access controls is an alternative.
4. `--target` is resolved or interpreted at the **remote exit**. The script sends DNS names using the SOCKS5 domain type without locally resolving the target.

```bash
python3 scripts/compare_transports.py \
  --proxy FoxTunnel=127.0.0.1:1080 \
  --proxy VLESS-Vision=127.0.0.1:1081 \
  --target 127.0.0.1:9000 \
  --rounds 20 --parallel 4 --warmup 2 \
  --bytes 4194304 --timeout 20 \
  --out comparison-001.json
```

Use another Xray SOCKS5 inbound for VLESS + XHTTP or run a separate comparison. Existing output JSON is never overwritten.

## Report interpretation

- `connect_p50_ms` / `connect_p95_ms` includes local SOCKS TCP setup and remote CONNECT; tunnel implementations may reuse upstream TLS connections.
- `payload_median_mbps` / `payload_p95_mbps` measures **megabits/second per successful verified echo flow**, excluding connection setup. Each payload byte is counted **once**, not twice for upload and echo.
- `successful/attempted`, `failed` and per-sample errors must be evaluated alongside speed: **only successes** contribute throughput values.
- `--parallel N` runs N simultaneous flows for **one** candidate. Candidate proxies run sequentially within a round, with order rotating between rounds. The reported per-flow throughput is not N-flow aggregate bandwidth.

**This is not a DPI-resistance result, Firefox fingerprint equivalence claim or Russian ISP field test.** The full SOCKS → client → transport → remote exit → echo chain is measured. CPU/RSS, retransmissions and real packet loss are not included. Use `ft-webprofile` and separate packet captures for fingerprint work.

Keep FoxTunnel Git SHA, Xray version, precise VLESS configuration, Go/NSS/Neqo backend, VDS and public egress IP, MTU, client OS, operator/region, date/time, RTT/loss, CPU/RSS and workload settings alongside each JSON report. Repeat runs at multiple times, separately for each operator. ISP allowlist access requires testing the **specific destination IP**; packet captures may contain private metadata and should not be automatically published.

## Offline self-test

```bash
python3 -m unittest discover -s scripts -p 'test_compare_transports.py' -v
```

The tests exercise a **fake SOCKS5 endpoint**, not a real VLESS/FoxTunnel deployment.
