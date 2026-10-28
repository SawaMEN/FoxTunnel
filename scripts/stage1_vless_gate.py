#!/usr/bin/env python3
"""Conservative VetroffProxy vs VLESS Stage 1 gate: three matched WAN days.

Input must be redacted stage1_vless.py reports. Review topology, process
identity and VLESS configuration manually: software cannot attest them.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import statistics
import sys
from pathlib import Path

KIND = "vetroff-vless-stage1"


def finite_nonnegative(x) -> bool:
    return type(x) in (int, float) and math.isfinite(x) and x >= 0


def percentile(values: list[float], q: float) -> float:
    values = sorted(values)
    pos = (len(values) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] + (values[hi] - values[lo]) * (pos - lo)


def load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != 2 or data.get("kind") != KIND:
        raise ValueError("not a stage1 redacted report")
    return data


def per_proxy(report: dict, label: str) -> dict:
    c = report["configuration"]
    n = c["rounds"] * c["parallel"]
    if (type(n) is not int or n < 5 or n > 32000 or
            not 1 <= c["rounds"] <= 1000 or not 1 <= c["parallel"] <= 32):
        raise ValueError("invalid sample count or measurement configuration")
    rows = [r for r in report["samples"] if r["proxy"] == label]
    if len(rows) != n or any(r["proxy"] not in ("fox", "vless") for r in report["samples"]):
        raise ValueError("unexpected sample count or proxy label")
    seen = set()
    for r in rows:
        key = (r["round"], r["flow"])
        if (key in seen or type(r["round"]) is not int or type(r["flow"]) is not int
                or not 1 <= r["round"] <= c["rounds"] or not 1 <= r["flow"] <= c["parallel"]):
            raise ValueError("duplicate or invalid sample identity")
        seen.add(key)
        if type(r["ok"]) is not bool or type(r["integrity_failure"]) is not bool:
            raise ValueError("invalid sample flags")
        if r["ok"] and (not finite_nonnegative(r["connect_ms"]) or
                        not finite_nonnegative(r["transfer_ms"]) or
                        not finite_nonnegative(r["completion_ms"]) or
                        abs(r["completion_ms"] - r["connect_ms"] - r["transfer_ms"]) > .005 or
                        not finite_nonnegative(r["payload_mbps"]) or r["payload_mbps"] <= 0 or
                        r["integrity_failure"]):
            raise ValueError("successful sample contains invalid measurement")
    good = [r for r in rows if r["ok"]]
    return {
        "attempted": n, "successful": len(good),
        "success_percent": round(100 * len(good) / n, 3),
        "integrity_failures": sum(bool(r["integrity_failure"]) for r in rows),
        "connect_p95_ms": round(percentile([r["connect_ms"] for r in good], .95), 3)
                          if good else None,
        "payload_median_mbps": round(statistics.median(r["payload_mbps"] for r in good), 3)
                               if good else None,
        "completion_p95_ms": round(percentile([r["completion_ms"] for r in good], .95), 3)
                             if good else None,
    }


def ratio(a: float | None, b: float | None) -> float | None:
    if a is None or b is None or b <= 0:
        return None
    return round(a / b, 4)


def evaluate(reports: list[dict]) -> dict:
    issues: list[str] = []
    if not reports:
        raise ValueError("at least one report is required")
    scenario = reports[0].get("scenario")
    if scenario not in ("small", "bulk"):
        raise ValueError("unknown scenario")
    configuration = reports[0]["configuration"]
    days: set[str] = set()
    detail: list[dict] = []
    for report in reports:
        if report.get("kind") != KIND or report.get("schema") != 2:
            raise ValueError("unknown report kind or schema")
        if report.get("scenario") != scenario or report.get("configuration") != configuration:
            raise ValueError("mixed scenarios or measurement configurations")
        if (not 1 <= configuration["bytes_per_flow"] <= 1024 ** 3
                or not 1 <= configuration["timeout_seconds"] <= 120
                or configuration.get("fox_transport") not in
                ("h2-connect", "h2-post", "h3-post", "wss", "xhttp-stream-one",
                 "xhttp-stream-up", "xhttp-packet-up")
                or configuration.get("vless_transport") not in
                ("reality-vision", "xhttp", "other")):
            raise ValueError("invalid or unidentified benchmark configuration")
        day = dt.datetime.fromisoformat(report["created_at_utc"])
        if day.tzinfo is None or day.utcoffset() is None:
            raise ValueError("timestamp must have a timezone")
        days.add(day.astimezone(dt.timezone.utc).date().isoformat())
        if report.get("environment") != "wan" or report.get("wan_attested_by_operator") is not True:
            issues.append("WAN topology not operator-attested")
        fox = per_proxy(report, "fox")
        vless = per_proxy(report, "vless")
        if len(report["samples"]) != 2 * configuration["rounds"] * configuration["parallel"]:
            raise ValueError("extra sample rows")
        speed = ratio(fox["payload_median_mbps"], vless["payload_median_mbps"])
        latency = ratio(fox["connect_p95_ms"], vless["connect_p95_ms"])
        completion = ratio(fox["completion_p95_ms"], vless["completion_p95_ms"])
        if any(r["success_percent"] < 99 for r in (fox, vless)):
            issues.append("success rate below 99%")
        if any(r["integrity_failures"] for r in (fox, vless)):
            issues.append("verified echo integrity failure")
        if scenario == "bulk" and (speed is None or speed < .9):
            issues.append("VetroffProxy median goodput below 90% VLESS")
        if scenario == "small" and (completion is None or completion > 1.1):
            issues.append("VetroffProxy p95 end-to-end latency above 110% VLESS")
        if scenario == "bulk" and (latency is None or latency > 1.1):
            issues.append("VetroffProxy p95 CONNECT latency above 110% VLESS")
        resource = report.get("resources")
        cpu_ratio = mem_ratio = None
        if isinstance(resource, dict) and set(resource) == {"fox", "vless"}:
            for label in ("fox", "vless"):
                r = resource[label]
                if not finite_nonnegative(r["cpu_percent_one_core"]) or not finite_nonnegative(r["rss_peak_mib"]):
                    raise ValueError("invalid resource metrics")
            cpu_ratio = ratio(resource["fox"]["cpu_percent_one_core"],
                              resource["vless"]["cpu_percent_one_core"])
            mem_ratio = ratio(resource["fox"]["rss_peak_mib"], resource["vless"]["rss_peak_mib"])
        if scenario == "bulk":
            if cpu_ratio is None or mem_ratio is None:
                issues.append("CPU/RSS comparison missing or unusable")
            else:
                if cpu_ratio > 1.2:
                    issues.append("VetroffProxy CPU use above 120% VLESS")
                if mem_ratio > 1.2:
                    issues.append("VetroffProxy RSS above 120% VLESS")
        detail.append({"utc_day": day.astimezone(dt.timezone.utc).date().isoformat(),
                       "fox": fox, "vless": vless,
                       "fox_to_vless": {"goodput_ratio": speed,
                                        "connect_p95_ratio": latency,
                                        "completion_p95_ratio": completion,
                                        "cpu_ratio": cpu_ratio, "rss_ratio": mem_ratio}})
    if len(days) < 3:
        issues.append("at least three different UTC measurement days required")
    if len(reports) < 3:
        issues.append("at least three matched reports required")
    return {"schema": 2, "kind": "vetroff-vless-stage1-gate",
            "scenario": scenario, "passed": not issues,
            "wan_verified_by_tool": False, "issues": sorted(set(issues)),
            "days_observed": len(days), "measurements": detail,
            "limitations": [
                "Operator attestation is not independently verified.",
                "Passing TCP metrics cannot establish UDP, DPI or leak protection.",
                "Review workload, independent routes, client versions and process PIDs manually.",
            ]}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", type=Path, action="append", required=True,
                   help="repeat with matched small OR bulk report from three different UTC days")
    p.add_argument("--out", type=Path, required=True, help="new sanitized JSON verdict")
    args = p.parse_args(argv)
    try:
        if args.out.exists() or not args.out.parent.is_dir():
            raise ValueError("output already exists or parent directory missing")
        verdict = evaluate([load(path) for path in args.report])
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(verdict, output, indent=2, sort_keys=True, allow_nan=False)
            output.write("\n")
        print(f"stage1 {verdict['scenario']}: {'PASS' if verdict['passed'] else 'FAIL'}; "
              f"{verdict['days_observed']} UTC days; {len(verdict['issues'])} issues")
        return 0 if verdict["passed"] else 2
    except (OSError, ValueError, KeyError, TypeError, IndexError, OverflowError):
        print("stage1 gate: failed safely (private report details omitted)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
