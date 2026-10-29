#!/usr/bin/env python3
"""Compare VetroffProxy vs Xray/VLESS UDP using two local SOCKS5 UDP associations.

The existing Stage 4 socket harness provides verified nonce-tagged UDP echoes.
Operator-provided proxy modes and WAN topology are not automatically verified.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import bond_stage4_field as udp
import compare_transports as tcp

ROOT = Path(__file__).resolve().parent
VETROFF_TRANSPORTS = ("h2-connect", "h2-post", "h3-post", "wss", "xhttp-stream-one",
                  "xhttp-stream-up", "xhttp-packet-up")
VLESS_TRANSPORTS = ("reality-vision", "xhttp", "other")
ERROR_TYPES = {"ConnectionError", "TimeoutError", "OSError", "ValueError",
               "BrokenPipeError", "ConnectionResetError"}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fox-socks", required=True, help="VetroffProxy local SOCKS5 HOST:PORT")
    p.add_argument("--vless-socks", required=True, help="Xray local SOCKS5 HOST:PORT")
    p.add_argument("--target", required=True, help="the SAME controlled UDP echo target for both")
    p.add_argument("--fox-transport", choices=VETROFF_TRANSPORTS)
    p.add_argument("--vless-transport", choices=VLESS_TRANSPORTS)
    p.add_argument("--environment", choices=("lab", "wan"), required=True)
    p.add_argument("--confirm-independent-vds", action="store_true",
                   help="operator attests independent external paths; NOT verified")
    p.add_argument("--rounds", type=int, default=40)
    p.add_argument("--parallel", type=int, default=2)
    p.add_argument("--warmup", type=int, default=3)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--budget-seconds", type=int, default=900)
    p.add_argument("--out", type=Path, required=True,
                   help="new private redacted report, never overwritten")
    return p


def validate(a: argparse.Namespace) -> None:
    fox, vless, target = (tcp.address(x) for x in (a.fox_socks, a.vless_socks, a.target))
    if fox == vless or target in (fox, vless):
        raise ValueError("SOCKS and echo endpoints must all differ")
    if not (5 <= a.rounds <= 200 and 1 <= a.parallel <= 8 and
            0 <= a.warmup <= 10 and .1 <= a.timeout <= 30 and
            30 <= a.budget_seconds <= 7200):
        raise ValueError("invalid measurement bounds")
    if a.confirm_independent_vds and a.environment != "wan":
        raise ValueError("WAN confirmation is valid only for WAN environment")
    if a.environment == "wan" and (not a.fox_transport or not a.vless_transport
                                    or not a.confirm_independent_vds):
        raise ValueError("WAN requires transport IDs and operator topology confirmation")
    if a.out.exists() or not a.out.parent.is_dir():
        raise ValueError("output exists or parent directory is missing")


def sanitize(row: dict) -> dict:
    raw = str(row.get("error_category") or "")
    category = raw if raw in ERROR_TYPES else ("other" if raw else None)
    return {
        "proxy": row["proxy"], "round": row["round"], "flow": row["flow"],
        "ok": row["ok"] is True, "rtt_ms": row.get("rtt_ms"),
        "error_category": category if not row["ok"] else None,
        # Stage4 udp_flow currently reports ValueError for both invalid SOCKS
        # packets and nonce / stale reply mismatches. Treat both as integrity
        # failures for a conservative comparison.
        "integrity_failure": not row["ok"] and category == "ValueError",
    }


def run(a: argparse.Namespace) -> dict:
    validate(a)
    with tempfile.TemporaryDirectory(prefix="ft-stage1-udp-private-") as d:
        raw_path = Path(d) / "raw.json"
        cmd = [sys.executable, str(ROOT / "bond_stage4_field.py"),
               "--mode", "udp", "--scenario", "stage1udp",
               "--environment", "lab",  # internal harness only; never let it assert WAN
               "--proxy", f"fox={a.fox_socks}", "--proxy", f"vless={a.vless_socks}",
               "--target", a.target, "--rounds", str(a.rounds),
               "--parallel", str(a.parallel), "--warmup", str(a.warmup),
               "--timeout", str(a.timeout), "--out", str(raw_path)]
        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False, timeout=a.budget_seconds)
        if not raw_path.is_file():
            raise RuntimeError("UDP harness produced no report")
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
    if (raw.get("schema") != 1 or raw.get("mode") != "udp" or
            set(raw.get("summary", {})) != {"fox", "vless"} or
            raw.get("configuration", {}).get("distinct_target_count") != 1):
        raise ValueError("unexpected UDP source report")
    rows = [sanitize(row) for row in raw["samples"]]
    rows.sort(key=lambda r: (r["proxy"], r["flow"], r["round"]))
    if len(rows) != 2 * a.rounds * a.parallel:
        raise ValueError("incomplete UDP report")
    return {
        "schema": 1, "kind": "vetroff-vless-stage1-udp",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "environment": a.environment,
        "wan_attested_by_operator": a.environment == "wan" and a.confirm_independent_vds,
        "wan_verified_by_tool": False,
        "configuration": {
            "rounds": a.rounds, "parallel": a.parallel, "warmup": a.warmup,
            "timeout_seconds": a.timeout, "distinct_target_count": 1,
            "fox_transport": a.fox_transport, "vless_transport": a.vless_transport,
        },
        "samples": rows,
        "limitations": [
            "UDP echo request/response latency includes SOCKS and proxy overhead, NOT ICMP ping.",
            "Failures include timeouts, refused SOCKS associations and malformed replies; they are NOT physical packet-loss measurements.",
            "Jitter is mean absolute consecutive successful RTT delta per flow, NOT RFC3550 jitter.",
            "A single controlled destination is shared; routes, VDS identity, and declared protocols are NOT independently verified.",
            "This test does not assess congestion under load, censorship resistance, or UDP/TUN leaks.",
        ],
    }


def main(argv=None) -> int:
    a = parser().parse_args(argv)
    try:
        result = run(a)
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(result, out, indent=2, sort_keys=True, allow_nan=False)
            out.write("\n")
        for label in ("fox", "vless"):
            rows = [r for r in result["samples"] if r["proxy"] == label]
            summary = udp.summarize(rows, "udp")
            print(f"{label}: {summary['successful']}/{summary['attempted']} UDP echoes; "
                  f"p95 {summary['rtt_p95_ms']} ms; failure {summary['loss_pct']}%")
        print("private redacted UDP report written")
        return 0 if all(any(r["ok"] for r in result["samples"] if r["proxy"] == label)
                        for label in ("fox", "vless")) else 2
    except (OSError, ValueError, TypeError, KeyError, RuntimeError,
            subprocess.SubprocessError, json.JSONDecodeError):
        print("stage1 UDP failed (private endpoints omitted)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
