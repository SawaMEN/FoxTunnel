#!/usr/bin/env python3
"""Stage 3: confidential matched SOCKS TCP echo from baseline, candidate and VLESS.

Three independently launched SOCKS clients and a controlled echo target are
required. The code neither provisions VDS nor proves the actual network path.
Never publish the raw underlying compare_transports.py output.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time

import compare_transports as bench
import stage1_vless as stage1

LABELS = ("baseline", "candidate", "vless")
SHA = re.compile(r"[a-fA-F0-9]{40}\Z")
TRANSPORTS = ("h2-connect", "h2-post", "h3-post", "wss",
              "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up")
VLESS = ("reality-vision", "xhttp", "other")


class TripleSampler(stage1.ResourceSampler):
    """Adapt Stage 1's Linux /proc PID-identity protection to three clients."""

    def finish(self) -> dict | None:
        if not self.pids:
            return None
        self.stopped.set()
        if self.worker:
            self.worker.join(timeout=2)
        self.poll()
        if self.errors or set(self.last) != set(LABELS):
            raise ValueError("three-client resource sampling incomplete")
        duration = max(time.monotonic() - self.started, 1e-6)
        ticks_per_second = os.sysconf("SC_CLK_TCK")
        return {
            label: {
                "cpu_percent_one_core": round(
                    100 * (self.last[label][0] - self.first[label][0])
                    / ticks_per_second / duration, 3),
                "rss_peak_mib": round(self.peaks[label] / 1024, 3),
            }
            for label in LABELS
        }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    for label in LABELS:
        p.add_argument(f"--{label}-socks", required=True)
        p.add_argument(f"--{label}-pid", type=int,
                       help="Linux process PID (supply all three or none)")
    p.add_argument("--target", required=True,
                   help="operator-controlled private TCP echo HOST:PORT")
    p.add_argument("--baseline-sha", required=True)
    p.add_argument("--candidate-sha", required=True)
    p.add_argument("--fox-transport", required=True, choices=TRANSPORTS,
                   help="must be identical in baseline and candidate")
    p.add_argument("--vless-transport", required=True, choices=VLESS)
    p.add_argument("--scenario", required=True, choices=("small", "bulk"))
    p.add_argument("--environment", required=True, choices=("lab", "wan"))
    p.add_argument("--confirm-independent-vds", action="store_true",
                   help="operator assertion only; NOT checked by the tool")
    p.add_argument("--rounds", type=int, default=30)
    p.add_argument("--parallel", type=int, default=2)
    p.add_argument("--warmup", type=int, default=2)
    p.add_argument("--bytes", type=int, default=None)
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--budget-seconds", type=int, default=3600)
    p.add_argument("--out", required=True, type=Path)
    return p


def validate(a: argparse.Namespace) -> int:
    sockets = [bench.address(getattr(a, f"{name}_socks")) for name in LABELS]
    target = bench.address(a.target)
    if len(set(sockets)) != 3 or target in sockets:
        raise ValueError("three distinct SOCKS listeners and separate echo target required")
    if not SHA.fullmatch(a.baseline_sha) or not SHA.fullmatch(a.candidate_sha) or (
            a.baseline_sha.lower() == a.candidate_sha.lower()):
        raise ValueError("distinct full 40-character source revision SHAs required")
    size = a.bytes if a.bytes is not None else (
        1024 if a.scenario == "small" else 32 << 20)
    if not (1 <= a.rounds <= 1000 and 1 <= a.parallel <= 32
            and 0 <= a.warmup <= 20 and 1 <= size <= 1 << 30
            and 1 <= a.timeout <= 120 and 30 <= a.budget_seconds <= 7200):
        raise ValueError("measurement parameters outside limits")
    if a.confirm_independent_vds and a.environment != "wan":
        raise ValueError("operator WAN attestation cannot be applied to lab")
    pids = [getattr(a, f"{name}_pid") for name in LABELS]
    if any(pid is not None for pid in pids):
        if (platform.system() != "Linux" or any(pid is None or pid <= 0 for pid in pids)
                or len(set(pids)) != 3):
            raise ValueError("all three positive distinct PIDs required on Linux")
    if a.out.is_symlink() or a.out.exists() or not a.out.parent.is_dir():
        raise ValueError("output path must be new with an existing parent")
    return size


def measure(a: argparse.Namespace) -> dict:
    size = validate(a)
    pids = {label: getattr(a, f"{label}_pid") for label in LABELS}
    sampler = TripleSampler(pids if all(v is not None for v in pids.values()) else {})
    with tempfile.TemporaryDirectory(prefix="ft-stage3-private-") as tmp:
        raw = Path(tmp) / "raw.json"
        cmd = [sys.executable, str(Path(__file__).resolve().parent / "compare_transports.py")]
        for label in LABELS:
            cmd += ["--proxy", f"{label}={getattr(a, f'{label}_socks')}"]
        cmd += ["--target", a.target, "--rounds", str(a.rounds),
                "--parallel", str(a.parallel), "--warmup", str(a.warmup),
                "--bytes", str(size), "--timeout", str(a.timeout),
                "--out", str(raw)]
        sampler.start()
        try:
            result = subprocess.run(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=a.budget_seconds, check=False)
        finally:
            resources = sampler.finish()
        if result.returncode not in (0, 2) or not raw.is_file():
            raise RuntimeError("three-way echo benchmark incomplete")
        detail = json.loads(raw.read_text(encoding="utf-8"))
    if detail.get("schema") != 1 or set(detail.get("summary", {})) != set(LABELS):
        raise ValueError("unexpected three-way raw report")
    samples = [stage1.sanitize(row) for row in detail["samples"]]
    if len(samples) != 3 * a.rounds * a.parallel:
        raise ValueError("incomplete measurement set")
    return {
        "schema": 1, "kind": "foxtunnel-stage3-3way",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scenario": a.scenario, "environment": a.environment,
        "wan_attested_by_operator": a.environment == "wan" and a.confirm_independent_vds,
        "wan_verified_by_tool": False,
        "configuration": {
            "baseline_sha": a.baseline_sha.lower(),
            "candidate_sha": a.candidate_sha.lower(),
            "fox_transport": a.fox_transport,
            "vless_transport": a.vless_transport,
            "bytes_per_flow": size, "rounds": a.rounds, "parallel": a.parallel,
            "warmup": a.warmup, "timeout_seconds": a.timeout,
        },
        "samples": samples, "resources": resources,
        "limitations": [
            "Only operator-attested WAN; infrastructure, versions and PID identity not verified.",
            "Comparisons include total SOCKS client and remote server behavior.",
            "Whole-process CPU/RSS are approximate; no VDS CPU/RSS instrumentation.",
            "No claim about UDP, DPI resistance or Firefox fingerprint.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        report = measure(args)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        for label in LABELS:
            ok = sum(row["ok"] for row in report["samples"] if row["proxy"] == label)
            print(f"{label}: {ok}/{args.rounds * args.parallel} verified echo transfers")
        print("Private three-way report saved; WAN environment not tool-verified.")
        return 0 if all(any(r["proxy"] == label and r["ok"]
                            for r in report["samples"]) for label in LABELS) else 2
    except (OSError, ValueError, KeyError, TypeError, RuntimeError,
            subprocess.SubprocessError, json.JSONDecodeError):
        print("stage3: measurement failed; private endpoints omitted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
