#!/usr/bin/env python3
"""Stage 1 UDP baseline gate against Xray/VLESS: three matched WAN UTC days.

All thresholds are proposed release criteria, NOT observed results.
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

KIND = "vetroff-vless-stage1-udp"
FOX = ("h2-connect", "h2-post", "h3-post", "wss",
       "xhttp-stream-one", "xhttp-stream-up", "xhttp-packet-up")
VLESS = ("reality-vision", "xhttp", "other")


def number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (pos - low), 3)


def ratio(a: float | None, b: float | None) -> float | None:
    return round(a / b, 4) if a is not None and b is not None and b > 0 else None


def read(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != 1 or doc.get("kind") != KIND:
        raise ValueError("not a Stage 1 UDP report")
    return doc


def summarize(rows: list[dict], config: dict, label: str) -> dict:
    rounds, parallel = config["rounds"], config["parallel"]
    expected = rounds * parallel
    if not (type(rounds) is int and type(parallel) is int and
            5 <= rounds <= 200 and 1 <= parallel <= 8 and
            expected >= 20):
        raise ValueError("insufficient UDP samples for a release gate")
    group = [r for r in rows if r["proxy"] == label]
    if len(group) != expected:
        raise ValueError("UDP samples missing")
    seen = set()
    per_flow: dict[int, list[tuple[int, float]]] = {}
    n_success = n_integrity = 0
    latencies = []
    for r in group:
        index = (r["round"], r["flow"])
        if (type(index[0]) is not int or type(index[1]) is not int or
                not 1 <= index[0] <= rounds or not 1 <= index[1] <= parallel or
                index in seen):
            raise ValueError("duplicate or invalid UDP sample")
        seen.add(index)
        if type(r["ok"]) is not bool or type(r["integrity_failure"]) is not bool:
            raise ValueError("invalid UDP sample flags")
        if r["ok"]:
            rtt = r["rtt_ms"]
            if not number(rtt) or rtt <= 0 or r["integrity_failure"] or r["error_category"] is not None:
                raise ValueError("invalid successful UDP echo")
            n_success += 1
            latencies.append(rtt)
            per_flow.setdefault(r["flow"], []).append((r["round"], rtt))
        else:
            if r["rtt_ms"] is not None or r["error_category"] is None:
                raise ValueError("invalid failed UDP echo")
        n_integrity += r["integrity_failure"]
    differences = []
    for flow in per_flow.values():
        flow.sort()
        differences.extend(abs(y[1] - x[1]) for x, y in zip(flow, flow[1:]))
    return {
        "attempted": expected, "successful": n_success,
        "success_percent": round(100 * n_success / expected, 3),
        "failure_percent": round(100 * (expected - n_success) / expected, 3),
        "integrity_failures": n_integrity,
        "rtt_p95_ms": percentile(latencies, .95),
        "jitter_mean_abs_delta_ms": round(statistics.mean(differences), 3)
                                   if differences else None,
    }


def evaluate(reports: list[dict]) -> dict:
    if not reports:
        raise ValueError("at least one UDP report is required")
    template = reports[0]["configuration"]
    if (template.get("fox_transport") not in FOX or
            template.get("vless_transport") not in VLESS or
            template.get("distinct_target_count") != 1 or
            type(template.get("warmup")) is not int or not 0 <= template["warmup"] <= 10 or
            not number(template.get("timeout_seconds")) or
            not .1 <= template["timeout_seconds"] <= 30):
        raise ValueError("invalid UDP configuration or unspecified transports")
    days = set()
    issues = []
    rows_out = []
    for r in reports:
        if r.get("schema") != 1 or r.get("kind") != KIND:
            raise ValueError("unknown UDP report version")
        if r.get("configuration") != template:
            raise ValueError("mixed UDP measurements")
        timepoint = dt.datetime.fromisoformat(r["created_at_utc"])
        if timepoint.tzinfo is None or timepoint.utcoffset() is None:
            raise ValueError("UDP report needs timestamp with timezone")
        day = timepoint.astimezone(dt.timezone.utc).date().isoformat()
        days.add(day)
        if r.get("environment") != "wan" or r.get("wan_attested_by_operator") is not True:
            issues.append("independent WAN topology not operator-attested")
        rows = r["samples"]
        if len(rows) != 2 * template["rounds"] * template["parallel"] or any(
                q.get("proxy") not in ("fox", "vless") for q in rows):
            raise ValueError("unexpected UDP sample count or label")
        fox = summarize(rows, template, "fox")
        vless = summarize(rows, template, "vless")
        rtt_ratio = ratio(fox["rtt_p95_ms"], vless["rtt_p95_ms"])
        if fox["success_percent"] < 99 or vless["success_percent"] < 99:
            issues.append("UDP echo success rate below 99%")
        if fox["integrity_failures"] or vless["integrity_failures"]:
            issues.append("UDP echo integrity error")
        if rtt_ratio is None or rtt_ratio > 1.1:
            issues.append("VetroffProxy UDP echo p95 above 110% VLESS")
        if fox["failure_percent"] > vless["failure_percent"] + 1:
            issues.append("VetroffProxy UDP failed-echo rate above VLESS by >1 pp")
        rows_out.append({
            "utc_day": day, "fox": fox, "vless": vless,
            "fox_to_vless_rtt_p95_ratio": rtt_ratio,
        })
    if len(reports) < 3 or len(days) < 3:
        issues.append("at least three distinct UTC days of matched UDP measurements required")
    return {
        "schema": 1, "kind": "vetroff-vless-stage1-udp-gate",
        "passed": not issues, "wan_verified_by_tool": False,
        "days_observed": len(days), "issues": sorted(set(issues)),
        "measurements": rows_out,
        "limitations": [
            "Operator-declared WAN and VLESS transport not independently verified.",
            "Failed UDP echoes include proxy errors and timeouts, not just physical packet loss.",
            "Jitter is descriptive; no release limit is inferred from a near-zero baseline.",
            "Passing the UDP echo gate is not proof of low game ping, TUN correctness or DPI resistance.",
        ],
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--report", action="append", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args(argv)
    try:
        if a.out.exists() or not a.out.parent.is_dir():
            raise ValueError("output already exists or parent missing")
        verdict = evaluate([read(path) for path in a.report])
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(verdict, output, indent=2, sort_keys=True, allow_nan=False)
            output.write("\n")
        print("stage1 UDP " + ("PASS" if verdict["passed"] else "FAIL") +
              f"; {verdict['days_observed']} UTC days; {len(verdict['issues'])} issues")
        return 0 if verdict["passed"] else 2
    except (OSError, ValueError, KeyError, IndexError, TypeError, OverflowError):
        print("stage1 UDP gate failed safely (private details omitted)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
