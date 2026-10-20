#!/usr/bin/env python3
"""Collect private, reproducible Go CPU/heap/block/mutex loopback profiles.

Run in a NEW directory outside the repository. No external target is dialed.
Profile files may contain raw symbols, paths and runtime metadata. Never upload
them to public CI artifacts or commit them to Git.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = {
    "go-h2": ("BenchmarkStage3GoH2", None),
    "go-h3": ("BenchmarkStage3GoH3", None),
    "nss-h2": ("BenchmarkStage3NSSH2", "nss"),
}
SCENARIOS = {"small": ("64B", 64), "bulk": ("1MiB", 1 << 20)}
BENCHTIME = re.compile(r"^(?:[1-9][0-9]{0,2}(?:ms|s)|[1-9][0-9]{0,3}x)$")
PROFILES = ("cpu", "mem", "block", "mutex")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--variant", required=True, choices=tuple(VARIANTS))
    p.add_argument("--scenario", required=True, choices=tuple(SCENARIOS))
    p.add_argument("--benchtime", default="1s",
                   help="duration (e.g. 250ms or 3s), or count (e.g. 100x)")
    p.add_argument("--out", required=True, type=Path,
                   help="new directory outside repository (private; never overwritten)")
    return p


def validate(a: argparse.Namespace) -> Path:
    if not BENCHTIME.fullmatch(a.benchtime):
        raise ValueError("benchtime outside bounded accepted syntax")
    if not a.out.parent.is_dir():
        raise ValueError("output parent does not exist")
    out = a.out.parent.resolve() / a.out.name
    if not a.out.name or a.out.name in (".", "..") or out.is_relative_to(ROOT):
        raise ValueError("profiles must be written outside source tree")
    if a.out.exists() or a.out.is_symlink():
        raise ValueError("output must be a new directory")
    return out


def parse_benchmark(log: str, variant: str, scenario: str) -> dict:
    name, _ = VARIANTS[variant]
    size_name, size = SCENARIOS[scenario]
    # Go testing prints GOMAXPROCS suffix and may pad cells arbitrarily.
    pattern = re.compile(
        rf"^({re.escape(name)}/{re.escape(size_name)}-\d+)\s+"
        r"([1-9]\d*)\s+(\d+(?:\.\d+)?) ns/op"
        r"(?:\s+(\d+(?:\.\d+)?) MB/s)?"
        r"\s+(\d+) B/op\s+(\d+) allocs/op$",
        re.MULTILINE,
    )
    matches = pattern.findall(log)
    if len(matches) != 1:
        raise ValueError("expected exactly one matching Go benchmark result")
    full, iterations, nanos, mbps, alloc_bytes, allocs = matches[0]
    ns = float(nanos)
    throughput = float(mbps) if mbps else None
    if not math.isfinite(ns) or ns <= 0 or (
            throughput is not None and (not math.isfinite(throughput) or throughput < 0)):
        raise ValueError("invalid benchmark duration or throughput")
    return {
        "benchmark": full, "bytes_per_exchange": size,
        "iterations": int(iterations), "ns_per_exchange": ns,
        "reported_mb_per_second": throughput,
        "bytes_allocated_per_exchange": int(alloc_bytes),
        "allocations_per_exchange": int(allocs),
    }


def create_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def run(a: argparse.Namespace) -> dict:
    directory = validate(a)
    fn, tags = VARIANTS[a.variant]
    scenario, _ = SCENARIOS[a.scenario]
    directory.mkdir(mode=0o700)
    # Enforce permissions even under unusual umask; generated Go pprof files
    # inherit the restrictive subprocess umask below.
    directory.chmod(0o700)
    output_paths = {kind: directory / (kind + ".pprof") for kind in PROFILES}
    cmd = ["go", "test"]
    if tags is not None:
        cmd += ["-tags", tags]
    cmd += ["./internal/tunnel", "-run", "^$", "-bench",
            f"^{fn}$" + "/" + f"^{scenario}$",
            "-benchmem", f"-benchtime={a.benchtime}", "-count=1",
            "-timeout=180s",
            f"-cpuprofile={output_paths['cpu']}",
            f"-memprofile={output_paths['mem']}",
            f"-blockprofile={output_paths['block']}",
            f"-mutexprofile={output_paths['mutex']}"]
    previous_umask = os.umask(0o077) if os.name == "posix" else None
    try:
        toolchain = subprocess.run(
            ["go", "version"], cwd=ROOT, capture_output=True, timeout=30,
            stdin=subprocess.DEVNULL, check=True,
        )
        process = subprocess.run(
            cmd, cwd=ROOT, capture_output=True, timeout=240,
            stdin=subprocess.DEVNULL, check=False,
        )
    finally:
        if previous_umask is not None:
            os.umask(previous_umask)
    create_private(directory / "go-test.log", process.stdout + b"\n" + process.stderr)
    if process.returncode != 0:
        raise RuntimeError("Go benchmark failed; inspect private go-test.log")
    result = parse_benchmark(process.stdout.decode("utf-8", errors="replace"),
                             a.variant, a.scenario)
    for p in output_paths.values():
        if not p.is_file() or p.stat().st_size == 0:
            raise RuntimeError("Go did not produce a complete set of profiles")
        if os.name == "posix" and p.stat().st_mode & 0o077:
            raise RuntimeError("profile has overly broad access permissions")
    report = {
        "schema": 1, "kind": "foxtunnel-stage3-local-profile",
        "variant": a.variant, "scenario": a.scenario,
        "go_version": toolchain.stdout.decode("utf-8", "replace").strip(),
        "benchtime": a.benchtime, "benchmark": result,
        "profile_files": {k: p.name for k, p in output_paths.items()},
        "environment": "loopback",
        "limitations": [
            "No external WAN/VDS or VLESS comparison; no throughput improvement claim.",
            "Go CPU profiles do not include libnss C execution time.",
            "Benchmark setup (TLS handshake, new SOCKS connection) occurs outside timed body.",
            "Profiles include network/setup runtime samples but not application secrets.",
            "Some profile types may contain paths or sensitive debugging metadata; keep private.",
        ],
    }
    create_private(directory / "summary.json", (
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8"))
    return report


def main(argv=None) -> int:
    a = parser().parse_args(argv)
    try:
        report = run(a)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        print("Stage 3 profiling failed; inspect private directory if it was created.",
              file=sys.stderr)
        return 2
    measure = report["benchmark"]
    print(f"{report['variant']} {report['scenario']}: "
          f"{measure['ns_per_exchange']} ns/exchange, "
          f"{measure['bytes_allocated_per_exchange']} B/op, "
          f"{measure['allocations_per_exchange']} allocs/op; "
          "private profiles saved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
