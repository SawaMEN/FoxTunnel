#!/usr/bin/env python3
"""Conservative Stage 3 three-way TCP gate; six WAN reports, three UTC days each.

No software can prove independently owned VDS, genuine binary revisions,
matching routes, or a clean benchmark host from operator-provided reports.
A PASS is a conditional result, NOT a certified performance improvement.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
import statistics
import sys

import stage3_wan as runner

SCENARIOS = ("small", "bulk")


def finite(x) -> bool:
    return type(x) in (int, float) and math.isfinite(x) and x >= 0


def percentile(items: list[float], q: float) -> float | None:
    if not items:
        return None
    values = sorted(items)
    idx = (len(values) - 1) * q
    lo = int(idx)
    hi = min(lo + 1, len(values) - 1)
    return round(values[lo] + (values[hi] - values[lo]) * (idx - lo), 3)


def ratio(a, b):
    return round(a / b, 4) if a is not None and b is not None and b > 0 else None


def load(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != 2 or doc.get("kind") != "foxtunnel-stage3-3way":
        raise ValueError("not a stage3 three-way sanitized report")
    return doc


def proxy_stats(rows: list[dict], label: str, cfg: dict) -> dict:
    count = cfg["rounds"] * cfg["parallel"]
    subset = [row for row in rows if row["proxy"] == label]
    if len(subset) != count:
        raise ValueError("missing or extra samples for " + label)
    seen = set()
    for row in subset:
        rid = (row["round"], row["flow"])
        if (type(row["round"]) is not int or type(row["flow"]) is not int or
                not 1 <= row["round"] <= cfg["rounds"] or
                not 1 <= row["flow"] <= cfg["parallel"] or rid in seen):
            raise ValueError("invalid or duplicate round/flow")
        seen.add(rid)
        if type(row["ok"]) is not bool or type(row["integrity_failure"]) is not bool:
            raise ValueError("invalid success flags")
        if row["ok"]:
            if (not finite(row["connect_ms"]) or not finite(row["transfer_ms"]) or
                    not finite(row["completion_ms"]) or not finite(row["payload_mbps"]) or
                    row["payload_mbps"] <= 0 or row["integrity_failure"] or
                    abs(row["completion_ms"] - row["connect_ms"] - row["transfer_ms"]) > 0.005):
                raise ValueError("inconsistent successful echo sample")
    successful = [row for row in subset if row["ok"]]
    return {
        "attempted": count, "successful": len(successful),
        "success_percent": round(100 * len(successful) / count, 3),
        "integrity_failures": sum(row["integrity_failure"] for row in subset),
        "connect_p95_ms": percentile([r["connect_ms"] for r in successful], .95),
        "completion_p95_ms": percentile([r["completion_ms"] for r in successful], .95),
        "median_mbps": round(statistics.median(r["payload_mbps"] for r in successful), 3)
                       if successful else None,
    }


def validate_config(config: dict) -> None:
    if (not isinstance(config, dict) or
            set(config) != {"baseline_sha", "candidate_sha", "fox_transport",
                            "vless_transport", "bytes_per_flow", "rounds", "parallel",
                            "warmup", "timeout_seconds"} or
            not runner.SHA.fullmatch(config["baseline_sha"]) or
            not runner.SHA.fullmatch(config["candidate_sha"]) or
            config["baseline_sha"].lower() == config["candidate_sha"].lower() or
            config["fox_transport"] not in runner.TRANSPORTS or
            config["vless_transport"] not in runner.VLESS or
            type(config["rounds"]) is not int or type(config["parallel"]) is not int or
            type(config["warmup"]) is not int or
            type(config["bytes_per_flow"]) is not int or
            not 1 <= config["rounds"] <= 1000 or
            not 1 <= config["parallel"] <= 32 or
            not 0 <= config["warmup"] <= 20 or
            not 1 <= config["bytes_per_flow"] <= 1 << 30 or
            not finite(config["timeout_seconds"]) or
            not 1 <= config["timeout_seconds"] <= 120 or
            config["rounds"] * config["parallel"] < 30):
        raise ValueError("invalid or undersampled stage3 benchmark configuration")


def evaluate(reports: list[dict]) -> dict:
    if not reports:
        raise ValueError("reports required")
    issues = []
    common = None
    seen = {scenario: set() for scenario in SCENARIOS}
    measurements = []
    for report in reports:
        if report.get("schema") != 2 or report.get("kind") != "foxtunnel-stage3-3way":
            raise ValueError("invalid report kind/schema")
        scenario = report.get("scenario")
        if scenario not in SCENARIOS:
            raise ValueError("unknown scenario")
        config = report["configuration"]
        validate_config(config)
        if scenario == "small" and config["bytes_per_flow"] != 1024:
            raise ValueError("stage3 small requires 1024-byte echo")
        if scenario == "bulk" and config["bytes_per_flow"] != 32 << 20:
            raise ValueError("stage3 bulk requires 32-MiB echo")
        constant = {k: v for k, v in config.items() if k != "bytes_per_flow"}
        if common is None:
            common = constant
        elif constant != common:
            raise ValueError("mixed client revisions, transports or benchmark parameters")
        start = dt.datetime.fromisoformat(report["started_at_utc"])
        finish = dt.datetime.fromisoformat(report["finished_at_utc"])
        created = dt.datetime.fromisoformat(report["created_at_utc"])
        if any(t.tzinfo is None or t.utcoffset() is None for t in (start, finish, created)):
            raise ValueError("start/finish/creation timestamps must have a timezone")
        start, finish, created = (t.astimezone(dt.timezone.utc)
                                  for t in (start, finish, created))
        elapsed = (finish - start).total_seconds()
        # A run overlapping two calendar dates is not an unambiguous UTC-day
        # measurement; it must not count toward the three-day gate.
        if start.date() != finish.date():
            raise ValueError("benchmark crossed UTC day boundary")
        if elapsed <= 0 or elapsed > 7260 or abs((created - finish).total_seconds()) > 1:
            raise ValueError("invalid benchmark capture interval")
        day = start.date().isoformat()
        if day in seen[scenario]:
            raise ValueError("duplicate UTC day for scenario")
        seen[scenario].add(day)
        warmup = report.get("warmup_failures")
        if (not isinstance(warmup, dict) or set(warmup) != set(runner.LABELS) or
                any(type(warmup[label]) is not int or
                    not 0 <= warmup[label] <= config["warmup"] * config["parallel"]
                    for label in runner.LABELS)):
            raise ValueError("missing or invalid warmup counts")
        if any(warmup[label] for label in runner.LABELS):
            issues.append("SOCKS warmup failures observed")
        if report.get("environment") != "wan" or report.get("wan_attested_by_operator") is not True:
            issues.append("operator WAN attestation missing")
        if report.get("wan_verified_by_tool") is not False:
            raise ValueError("untruthful automated WAN attestation")
        rows = report["samples"]
        if len(rows) != 3 * config["rounds"] * config["parallel"] or (
                {r["proxy"] for r in rows} != set(runner.LABELS)):
            raise ValueError("wrong sample population")
        stats = {label: proxy_stats(rows, label, config) for label in runner.LABELS}
        if any(m["success_percent"] < 99 for m in stats.values()):
            issues.append("echo success below 99%")
        if any(m["integrity_failures"] for m in stats.values()):
            issues.append("echo integrity mismatch")
        candidate = stats["candidate"]
        contrasts = {}
        for reference in ("baseline", "vless"):
            other = stats[reference]
            bulk_speed = ratio(candidate["median_mbps"], other["median_mbps"])
            connect = ratio(candidate["connect_p95_ms"], other["connect_p95_ms"])
            complete = ratio(candidate["completion_p95_ms"], other["completion_p95_ms"])
            contrasts[reference] = {
                "goodput_ratio": bulk_speed, "connect_p95_ratio": connect,
                "completion_p95_ratio": complete,
            }
            if scenario == "small" and (complete is None or complete > 1.1):
                issues.append(f"candidate small p95 above 110% {reference}")
            if scenario == "bulk" and (bulk_speed is None or bulk_speed < .9):
                issues.append(f"candidate bulk median below 90% {reference}")
            if scenario == "bulk" and (connect is None or connect > 1.1):
                issues.append(f"candidate CONNECT p95 above 110% {reference}")

        raw_resources = report.get("resources")
        resource_ratios = None
        if raw_resources is not None:
            if not isinstance(raw_resources, dict) or set(raw_resources) != set(runner.LABELS):
                raise ValueError("resource label mismatch")
            for label in runner.LABELS:
                data = raw_resources[label]
                if not isinstance(data, dict) or not (
                        finite(data.get("cpu_percent_one_core")) and
                        finite(data.get("rss_peak_mib"))):
                    raise ValueError("invalid resource readings")
            resource_ratios = {
                reference: {
                    "cpu_ratio": ratio(raw_resources["candidate"]["cpu_percent_one_core"],
                                       raw_resources[reference]["cpu_percent_one_core"]),
                    "rss_ratio": ratio(raw_resources["candidate"]["rss_peak_mib"],
                                       raw_resources[reference]["rss_peak_mib"]),
                }
                for reference in ("baseline", "vless")
            }
        if scenario == "bulk":
            if resource_ratios is None:
                issues.append("bulk CPU/RSS monitoring missing for three clients")
            else:
                for reference, values in resource_ratios.items():
                    if values["cpu_ratio"] is None or values["cpu_ratio"] > 1.2:
                        issues.append(f"candidate CPU above 120% {reference} or unusable")
                    if values["rss_ratio"] is None or values["rss_ratio"] > 1.2:
                        issues.append(f"candidate RSS above 120% {reference} or unusable")
        measurements.append({
            "utc_day": day, "scenario": scenario, "stats": stats,
            "candidate_vs": contrasts, "resource_ratios": resource_ratios,
            "warmup_failures": {label: warmup[label] for label in runner.LABELS},
            "duration_seconds": round(elapsed, 3),
        })
    for scenario in SCENARIOS:
        if len(seen[scenario]) < 3:
            issues.append("three distinct UTC days of " + scenario + " required")
    if seen["small"] != seen["bulk"]:
        issues.append("small and bulk must cover matching UTC days")
    return {
        "schema": 1, "kind": "foxtunnel-stage3-3way-gate",
        "passed": not issues, "issues": sorted(set(issues)),
        "wan_verified_by_tool": False,
        "baseline_sha": common["baseline_sha"], "candidate_sha": common["candidate_sha"],
        "observed_utc_days": {scenario: len(seen[scenario]) for scenario in SCENARIOS},
        "measurements": sorted(measurements, key=lambda v: (v["utc_day"], v["scenario"])),
        "limitations": [
            "PASS means an operator-attested threshold check, not verified WAN topology.",
            "No independent confirmation of binary identities, client transport or VDS class.",
            "Performance improvement is not proven by a no-regression gate alone.",
            "This suite does not measure UDP, DPI resistance or Neqo native CPU time.",
        ],
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", type=Path, required=True, action="append")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.out.is_symlink() or args.out.exists() or not args.out.parent.is_dir():
            raise ValueError("output must be new")
        result = evaluate([load(path) for path in args.report])
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        print(f"Stage3: {'CONDITIONAL PASS' if result['passed'] else 'FAIL'}; "
              f"small days {result['observed_utc_days']['small']}, "
              f"bulk days {result['observed_utc_days']['bulk']}; "
              f"{len(result['issues'])} issues")
        return 0 if result["passed"] else 2
    except (ValueError, OSError, KeyError, TypeError, IndexError, OverflowError, json.JSONDecodeError):
        print("Stage3 gate rejected reports; private paths omitted", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
