#!/usr/bin/env bash
# Stage-4 real FoxTunnel socket smoke on CI loopback ONLY.
# Never present resulting numbers as independent VDS/WAN evidence.
set -euo pipefail
umask 077
work="$(mktemp -d)"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

go build -o "$work/foxtunnel" ./cmd/foxtunnel
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "$work/key.pem" -out "$work/cert.pem" >/dev/null 2>&1

export FOXTUNNEL_USER=stage4-local
export FOXTUNNEL_PASSWORD
FOXTUNNEL_PASSWORD="$(openssl rand -hex 32)"
python3 scripts/echo_server.py --port 19000 >"$work/tcp-echo.log" 2>&1 &
pids+=("$!")
python3 scripts/udp_echo_server.py --port 19001 >"$work/udp-echo1.log" 2>&1 &
pids+=("$!")
python3 scripts/udp_echo_server.py --port 19002 >"$work/udp-echo2.log" 2>&1 &
pids+=("$!")

for port in 18443 18444; do
  "$work/foxtunnel" server \
    --listen "127.0.0.1:$port" --enable-udp --allow-private \
    --cert "$work/cert.pem" --key "$work/key.pem" \
    >"$work/server-$port.log" 2>&1 &
  pids+=("$!")
done

"$work/foxtunnel" client --server https://127.0.0.1:18443 \
  --sni localhost --ca-cert "$work/cert.pem" --listen 127.0.0.1:11080 \
  --enable-udp --udp-stream >"$work/client-legacy.log" 2>&1 &
pids+=("$!")
"$work/foxtunnel" client --server https://127.0.0.1:18443 \
  --fallback-server https://127.0.0.1:18444 \
  --sni localhost --ca-cert "$work/cert.pem" --listen 127.0.0.1:11081 \
  --enable-udp --udp-stream --udp-multi-node \
  >"$work/client-multi.log" 2>&1 &
pids+=("$!")

python3 - <<'PY'
import socket, time
ports = (19000, 18443, 18444, 11080, 11081)
for port in ports:
    for attempt in range(150):
        try:
            with socket.create_connection(("127.0.0.1", port), .2):
                break
        except OSError:
            time.sleep(.1)
    else:
        raise SystemExit(f"local lab service port {port} unavailable")
PY

python3 scripts/bond_stage4_field.py --mode tcp --environment lab \
  --scenario tcp-small --proxy legacy=127.0.0.1:11080 \
  --proxy adaptive=127.0.0.1:11081 \
  --target 127.0.0.1:19000 --bytes 8192 --rounds 4 --parallel 2 \
  --timeout 5 --warmup 1 --out "$work/tcp-lab.json"

python3 scripts/bond_stage4_field.py --mode udp --environment lab \
  --scenario udp-multi --proxy legacy=127.0.0.1:11080 \
  --proxy adaptive=127.0.0.1:11081 \
  --target 127.0.0.1:19001 --target 127.0.0.1:19002 \
  --rounds 4 --parallel 2 --timeout 5 --warmup 1 \
  --out "$work/udp-lab.json"

python3 - "$work/tcp-lab.json" "$work/udp-lab.json" <<'PY'
import json, sys
for path in sys.argv[1:]:
    report = json.load(open(path, encoding="utf-8"))
    assert report["environment"] == "lab"
    assert report["external_topology"] == "lab"
    for name, summary in report["summary"].items():
        assert summary["attempted"] == summary["successful"] == 8, (path, name, summary)
    print(f"local {report['mode']} socket smoke passed (NOT WAN evidence)")
PY
