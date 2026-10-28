#!/usr/bin/env python3
"""Stage 1 VetroffProxy vs Xray/VLESS: redacted matched SOCKS5 TCP echo measurements.

Both fully configured clients must already be running with local SOCKS5
listeners. The controlled echo target must be reachable through both exits.
This harness DOES NOT install Xray, provision VDS, or verify the WAN topology.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import compare_transports as bench

ROOT = Path(__file__).resolve().parent
ERROR_TYPES = {"ConnectionError", "TimeoutError", "OSError", "ValueError",
               "BrokenPipeError", "ConnectionResetError", "socket.timeout"}


def proc_sample(pid: int) -> tuple[int, int, int]:
    """Linux process CPU ticks and current RSS KiB; never record the PID."""
    stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    # comm is parenthesized and may contain spaces or closing parentheses.
    fields = stat[stat.rfind(")") + 2:].split()
    ticks = int(fields[11]) + int(fields[12])
    starttime = int(fields[19])
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if line.startswith("VmRSS:"):
            return ticks, int(line.split()[1]), starttime
    raise ValueError("VmRSS missing")


class ResourceSampler:
    def __init__(self, pids: dict[str, int]):
        self.pids = pids
        self.first: dict[str, tuple[int, int, int]] = {}
        self.last: dict[str, tuple[int, int, int]] = {}
        self.peaks: dict[str, int] = {}
        self.errors: list[str] = []
        self.stopped = threading.Event()
        self.worker: threading.Thread | None = None
        self.started = 0.0

    def poll(self) -> None:
        for name, pid in self.pids.items():
            try:
                ticks, rss, starttime = proc_sample(pid)
                if name in self.first and self.first[name][2] != starttime:
                    self.errors.append(name)  # PID reused/restarted: CPU comparison invalid
                self.last[name] = (ticks, rss, starttime)
                self.peaks[name] = max(rss, self.peaks.get(name, 0))
            except (OSError, ValueError, IndexError):
                self.errors.append(name)

    def start(self) -> None:
        if not self.pids:
            return
        self.started = time.monotonic()
        self.poll()
        self.first = dict(self.last)
        if len(self.first) != len(self.pids):
            raise ValueError("cannot read resource baseline for both processes")
        self.worker = threading.Thread(target=self._loop, daemon=True)
        self.worker.start()

    def _loop(self) -> None:
        while not self.stopped.wait(0.1):
            self.poll()

    def finish(self) -> dict | None:
        if not self.pids:
            return None
        self.stopped.set()
        if self.worker:
            self.worker.join(timeout=2)
        self.poll()
        if self.errors or set(self.last) != set(self.pids):
            raise ValueError("resource monitoring incomplete")
        elapsed = max(time.monotonic() - self.started, 1e-6)
        clock = os.sysconf("SC_CLK_TCK")
        return {
            name: {
                "cpu_percent_one_core": round(
                    100 * (self.last[name][0] - self.first[name][0]) / clock / elapsed, 3),
                "rss_peak_mib": round(self.peaks[name] / 1024, 3),
            }
            for name in ("fox", "vless")
        }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fox-socks", required=True, help="VetroffProxy local SOCKS5 HOST:PORT")
    p.add_argument("--vless-socks", required=True, help="Xray/VLESS local SOCKS5 HOST:PORT")
    p.add_argument("--target", required=True, help="controlled echo destination HOST:PORT")
    p.add_argument("--scenario", required=True, choices=("small", "bulk"))
    p.add_argument("--fox-transport", choices=("h2-connect", "h2-post", "h3-post", "wss",
                   "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up"))
    p.add_argument("--vless-transport", choices=("reality-vision", "xhttp", "other"))
    p.add_argument("--environment", required=True, choices=("lab", "wan"))
    p.add_argument("--confirm-independent-vds", action="store_true",
                   help="operator attests separate VDS and an external measured route; NOT independent verification")
    p.add_argument("--rounds", type=int, default=10)
    p.add_argument("--parallel", type=int, default=2)
    p.add_argument("--warmup", type=int, default=2)
    p.add_argument("--bytes", type=int, help="override 1024 (small) or 33554432 (bulk)")
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--budget-seconds", type=int, default=1800)
    p.add_argument("--fox-pid", type=int, help="running VetroffProxy client PID for Linux CPU/RSS")
    p.add_argument("--vless-pid", type=int, help="running Xray client PID for Linux CPU/RSS")
    p.add_argument("--out", required=True, type=Path, help="new sanitized JSON report (mode 0600)")
    return p


def validate(a: argparse.Namespace) -> int:
    fox, vless, target = (bench.address(x) for x in
                          (a.fox_socks, a.vless_socks, a.target))
    if fox == vless:
        raise ValueError("different local SOCKS listeners are required")
    if target in (fox, vless):
        raise ValueError("echo target cannot equal a SOCKS listener")
    size = a.bytes if a.bytes is not None else (1024 if a.scenario == "small" else 33554432)
    if not (1 <= a.rounds <= 1000 and 1 <= a.parallel <= 32 and
            0 <= a.warmup <= 20 and 1 <= size <= 1024 ** 3 and
            1 <= a.timeout <= 120 and 30 <= a.budget_seconds <= 7200):
        raise ValueError("measurement values out of bounds")
    if a.confirm_independent_vds and a.environment != "wan":
        raise ValueError("WAN attestation is valid only with --environment wan")
    if a.environment == "wan" and (not a.fox_transport or not a.vless_transport):
        raise ValueError("WAN measurements must identify both transport configurations")
    if (a.fox_pid is None) != (a.vless_pid is None):
        raise ValueError("provide both --fox-pid and --vless-pid, or neither")
    if a.fox_pid is not None:
        if platform.system() != "Linux":
            raise ValueError("process resource sampling is Linux-only")
        if a.fox_pid <= 0 or a.vless_pid <= 0 or a.fox_pid == a.vless_pid:
            raise ValueError("both PIDs must be distinct positive values")
    if a.out.exists() or not a.out.parent.is_dir():
        raise ValueError("report already exists or its parent is missing")
    return size


def sanitize(row: dict) -> dict:
    err = row.get("error") or ""
    kind = err.split(":", 1)[0]
    connect, transfer = row.get("connect_ms"), row.get("transfer_ms")
    completion = (round(connect + transfer, 3)
                  if row.get("ok") and isinstance(connect, (int, float))
                  and isinstance(transfer, (int, float)) else None)
    return {
        "proxy": row["proxy"], "round": row["round"], "flow": row["flow"],
        "ok": bool(row["ok"]), "connect_ms": connect,
        "transfer_ms": transfer, "completion_ms": completion,
        "payload_mbps": row.get("payload_mbps"),
        "error_category": (kind if kind in ERROR_TYPES else "other") if err else None,
        "integrity_failure": "echo mismatch" in err or "echo returned only" in err,
    }


def measure(a: argparse.Namespace) -> dict:
    size = validate(a)
    pids = ({"fox": a.fox_pid, "vless": a.vless_pid}
            if a.fox_pid is not None else {})
    sampler = ResourceSampler(pids)
    with tempfile.TemporaryDirectory(prefix="ft-stage1-private-") as d:
        raw_path = Path(d) / "raw.json"
        cmd = [sys.executable, str(ROOT / "compare_transports.py"),
               "--proxy", f"fox={a.fox_socks}", "--proxy", f"vless={a.vless_socks}",
               "--target", a.target, "--rounds", str(a.rounds),
               "--parallel", str(a.parallel), "--warmup", str(a.warmup),
               "--bytes", str(size), "--timeout", str(a.timeout),
               "--out", str(raw_path)]
        sampler.start()
        try:
            subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=a.budget_seconds, check=False)
        finally:
            resources = sampler.finish()
        if not raw_path.is_file():
            raise RuntimeError("benchmark did not produce a report")
        raw = json.loads(raw_path.read_text(encoding="utf-8"))
    if raw.get("schema") != 1 or set(raw.get("summary", {})) != {"fox", "vless"}:
        raise ValueError("unexpected benchmark report")
    clean = [sanitize(row) for row in raw["samples"]]
    return {
        "schema": 2, "kind": "vetroffproxy-vless-stage1",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scenario": a.scenario, "environment": a.environment,
        "wan_attested_by_operator": a.environment == "wan" and a.confirm_independent_vds,
        "wan_verified_by_tool": False,
        "configuration": {"bytes_per_flow": size, "rounds": a.rounds,
                          "parallel": a.parallel, "warmup": a.warmup,
                          "timeout_seconds": a.timeout,
                          "fox_transport": a.fox_transport,
                          "vless_transport": a.vless_transport},
        "summary": raw["summary"], "samples": clean, "resources": resources,
        "limitations": [
            "Two operator-configured SOCKS chains, not protocol-only measurements.",
            "No independent VDS, WAN route, actual VLESS mode or process identity verification.",
            "CPU/RSS are whole-process samples, potentially including unrelated work.",
            "This tool does not measure UDP, DPI resistance or Firefox equivalence.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = parser()
    a = p.parse_args(argv)
    try:
        report = measure(a)
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(report, out, indent=2, sort_keys=True, allow_nan=False)
            out.write("\n")
        for label, stats in report["summary"].items():
            print(f"{label}: {stats['successful']}/{stats['attempted']} verified; "
                  f"p95 connect {stats['connect_p95_ms']} ms; "
                  f"median echo {stats['payload_median_mbps']} Mbit/s")
        print(f"Private redacted report: {a.out}")
        return 0 if all(s["successful"] > 0 for s in report["summary"].values()) else 2
    except (ValueError, OSError, KeyError, TypeError, RuntimeError,
            subprocess.SubprocessError, json.JSONDecodeError):
        print("stage1: measurement failed (local paths/endpoints omitted)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
