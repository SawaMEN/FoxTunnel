#!/usr/bin/env python3
"""Bounded Linux-native TUN TCP/UDP/DNS soak resource gates (netns only).

The caller creates and owns isolated namespaces and real FoxTunnel processes.
Only /proc/<pid>/status and /proc/<pid>/fd are read; no host routes, firewall,
services or DNS configuration are changed by this module.
"""
from __future__ import annotations

import concurrent.futures
import os
from pathlib import Path
import sys
import time


# All resource caps apply separately to launcher, native TUN child and exit.
MAX_RSS_KIB = 768 * 1024
MAX_RSS_GROWTH_KIB = 128 * 1024
MAX_FDS = 512
MAX_FD_GROWTH = 48
MAX_SOCKET_GROWTH = 32
MAX_WORKERS = 3
# Match the longest native UDP flow inactivity timeout (30 seconds).
# A two-second cooldown falsely labels still-valid mappings as leaks.
IDLE_COOLDOWN_SECONDS = 34

# Exercises both address families and both DNS answer types.
PROBES = (
    ("tcp", "198.18.0.9", 5657),
    ("tcp", "fd42:2::9", 5657),
    ("udp", "198.18.0.9", 5656),
    ("udp", "fd42:2::9", 5656),
    ("dns6", "198.18.0.9", 53),
    ("dns", "fd42:2::9", 53),
)


def resources(pid: int) -> dict[str, int]:
    """Sample a live native process; failed/partial reads fail closed."""
    if sys.platform != "linux" or pid <= 0:
        raise RuntimeError("Linux positive process ID required for TUN soak")
    root = Path(f"/proc/{pid}")
    lines = (root / "status").read_text().splitlines()
    rss = next((int(line.split()[1]) for line in lines
                if line.startswith("VmRSS:")), None)
    if rss is None:
        raise RuntimeError(f"missing VmRSS for native process {pid}")
    descriptors = list((root / "fd").iterdir())
    sockets = 0
    live = 0
    for fd in descriptors:
        try:
            link = os.readlink(fd)
        except FileNotFoundError:
            continue  # One descriptor closed during enumeration.
        live += 1
        sockets += link.startswith("socket:[")
    if (root / "status").exists() is False:
        raise RuntimeError("process disappeared during resource sample")
    return {"rss_kib": rss, "fds": live, "socket_fds": sockets}


def evaluate(samples: list[dict[str, dict[str, int]]]) -> dict:
    """Gate limits and idle-end growth, retaining per-process evidence."""
    if len(samples) < 3:
        raise ValueError("need before, under-load and after samples")
    names = set(samples[0])
    if not names or any(set(sample) != names for sample in samples):
        raise ValueError("inconsistent resource process set")
    report = {}
    ok = True
    for name in sorted(names):
        rows = [sample[name] for sample in samples]
        keys = ("rss_kib", "fds", "socket_fds")
        if any(set(row) != set(keys) or any(not isinstance(row[k], int) or row[k] < 0 for k in keys)
               for row in rows):
            raise ValueError("invalid resource sample")
        first, last = rows[0], rows[-1]
        peak = {metric: max(row[metric] for row in rows) for metric in keys}
        growth = {metric: max(0, last[metric] - first[metric]) for metric in keys}
        within = (
            peak["rss_kib"] <= MAX_RSS_KIB
            and peak["fds"] <= MAX_FDS
            and growth["rss_kib"] <= MAX_RSS_GROWTH_KIB
            and growth["fds"] <= MAX_FD_GROWTH
            and growth["socket_fds"] <= MAX_SOCKET_GROWTH
        )
        report[name] = {
            "baseline": first,
            "peak": peak,
            "after_cooldown": last,
            "growth": growth,
            "passed": within,
        }
        ok = ok and within
    return {"passed": ok, "processes": report, "sample_count": len(samples),
            "limits": {"rss_kib": MAX_RSS_KIB,
                       "rss_growth_kib": MAX_RSS_GROWTH_KIB,
                       "fds": MAX_FDS, "fd_growth": MAX_FD_GROWTH,
                       "socket_growth": MAX_SOCKET_GROWTH}}


def run(namespace: str, pids: dict[str, int], duration: float, *,
        probe, sample=resources, sleep=time.sleep,
        clock=time.monotonic) -> dict:
    """Run bounded parallel new flows, sample resources and demand cleanup.

    probe(ns, kind, host, port) returns True only after checking the entire
    TCP echo, UDP echo or DNS A/AAAA wire response in the isolated namespace.
    Failures are counted rather than hidden or retried onto a different exit.
    """
    if not (1 <= duration <= 120) or set(pids) != {"launcher", "client", "exit"}:
        raise ValueError("bounded duration and three process identifiers required")
    if len(set(pids.values())) != 3:
        raise ValueError("resource process IDs must be distinct")
    samples = [{name: sample(pid) for name, pid in pids.items()}]
    counts = {kind: {"attempted": 0, "succeeded": 0} for kind in
              ("tcp", "udp", "dns", "dns6")}
    begin = clock()
    batches = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        while clock() - begin < duration:
            tasks = [pool.submit(probe, namespace, *case) for case in PROBES]
            for task, (kind, _, _) in zip(tasks, PROBES):
                succeeded = bool(task.result())
                counts[kind]["attempted"] += 1
                counts[kind]["succeeded"] += int(succeeded)
            samples.append({name: sample(pid) for name, pid in pids.items()})
            batches += 1
            sleep(0.25)
    elapsed = clock() - begin
    # The native forwarder permits non-DNS UDP mappings to remain idle
    # for 30 seconds. Wait past that genuine deadline before evaluating
    # persistent FD/socket growth; never call an active mapping a leak.
    sleep(IDLE_COOLDOWN_SECONDS)
    samples.append({name: sample(pid) for name, pid in pids.items()})
    resource_report = evaluate(samples)
    load_ok = (batches >= 2 and elapsed >= duration
               and all(v["succeeded"] == v["attempted"] for v in counts.values()))
    return {
        "schema": 1,
        "kind": "stage6-native-tun-netns-soak",
        "passed": load_ok and resource_report["passed"],
        "requested_seconds": duration,
        "elapsed_seconds": round(elapsed, 3),
        "batches": batches,
        "max_parallel": MAX_WORKERS,
        "idle_cooldown_seconds": IDLE_COOLDOWN_SECONDS,
        "load": counts,
        "resources": resource_report,
        "scope": ("Real native processes in isolated Linux netns only; RSS and "
                  "/proc fd/socket counters, not heap profiling or host leak proof."),
    }
