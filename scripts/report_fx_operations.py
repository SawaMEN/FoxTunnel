#!/usr/bin/env python3
"""Report Necko test-fixture resource efficiency with explicit comparability limits."""
import argparse
import json
import math
import os
from pathlib import Path

MODES = ("h2-connect", "h3-connect")
GIB = 1024 ** 3


def measures(result):
    if result.get("schema") != 1 or result.get("transport") not in MODES:
        raise ValueError("invalid soak schema or protocol")
    duration, rounds, payload = (result.get(key) for key in
                                 ("duration_seconds", "rounds", "payload_bytes_per_round"))
    samples = result.get("samples")
    warmup = result.get("warmup_tunnels")
    if any(type(n) is not int or n < 0 for n in (duration, rounds, payload, warmup)):
        raise ValueError("invalid soak workload")
    if duration < 10 or rounds <= 0 or payload <= 0 or not isinstance(samples, list) or len(samples) < 2:
        raise ValueError("incomplete soak workload or samples")
    counters = result.get("counters", {})
    expected = (rounds + warmup) * payload
    if (counters.get("upload_bytes") != expected or counters.get("download_bytes") != expected
        or counters.get("completed") != rounds + warmup or
        any(counters.get(field) != 0 for field in ("active", "draining", "rejected", "idle_expired"))):
        raise ValueError("incomplete transfer counters")
    for sample in samples:
        if any(type(sample.get(k)) is not int or sample[k] < 0
               for k in ("rss_kib", "cpu_ticks", "fds", "at_ms")):
            raise ValueError("invalid process sample")
    for a, b in zip(samples, samples[1:]):
        if b["at_ms"] < a["at_ms"] or b["cpu_ticks"] < a["cpu_ticks"]:
            raise ValueError("non-monotonic process samples")
    rate = result.get("cpu_ticks_per_second")
    cpu = result.get("cpu_seconds")
    if not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate <= 0 or (
        not isinstance(cpu, (int, float)) or not math.isfinite(cpu) or cpu < 0):
        raise ValueError("invalid CPU data")
    computed = (samples[-1]["cpu_ticks"] - samples[0]["cpu_ticks"]) / rate
    if not math.isclose(computed, cpu, rel_tol=.005, abs_tol=.03):
        raise ValueError("CPU sample mismatch")
    transferred_gib = 2 * rounds * payload / GIB  # exclude warmup from workload
    return {
        "transport": result["transport"],
        "duration_seconds": duration,
        "rounds": rounds,
        "parallel_streams": result.get("parallel_streams"),
        "payload_bytes_per_round": payload,
        "wire_app_gib": round(transferred_gib, 4),
        "app_mib_per_second": round(2 * rounds * payload / (1024 ** 2 * duration), 3),
        "cpu_seconds": round(cpu, 3),
        "cpu_seconds_per_gib": round(cpu / transferred_gib, 3),
        "rss_start_kib": samples[0]["rss_kib"],
        "rss_end_kib": samples[-1]["rss_kib"],
        "rss_max_sampled_kib": max(s["rss_kib"] for s in samples),
        "rss_delta_kib": samples[-1]["rss_kib"] - samples[0]["rss_kib"],
        "fd_max_sampled": max(s["fds"] for s in samples),
        "gc_collections": counters.get("gc_collections"),
        "gc_ms": counters.get("gc_ms"),
    }


def report(current, reference=None):
    now, before = {}, {}
    for mode in MODES:
        filename = mode + "-soak.json"
        now[mode] = measures(json.loads((current / filename).read_text()))
        if reference is not None:
            before[mode] = measures(json.loads((reference / filename).read_text()))
            keys = ("duration_seconds", "parallel_streams", "payload_bytes_per_round")
            if any(now[mode][key] != before[mode][key] for key in keys):
                raise ValueError("different test workload")
    return {
        "schema": 1,
        "kind": "fx-necko-resource-report",
        "current": now,
        "historical_reference": before if reference is not None else None,
        "comparison_validity": "uncontrolled-between-runs; do not infer speedup",
        "limits": [
            "Process RSS and CPU cover xpcshell helper only, not complete server/client.",
            "Wire application bytes include upload and download; no WAN throughput conclusion.",
            "Historical reference was measured on a different CI execution; CPU and RSS vary by host and runtime.",
            "These samples are not proof of lower allocations; inspect heap profiles before claims.",
            "Sampled peak RSS can miss true instantaneous peak."
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = report(args.current, args.reference)
    fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    for mode, value in result["current"].items():
        print(mode, "CPU s/GiB", value["cpu_seconds_per_gib"],
              "MiB/s", value["app_mib_per_second"],
              "sampled RSS peak KiB", value["rss_max_sampled_kib"])


if __name__ == "__main__":
    main()
