#!/usr/bin/env python3
"""Fail-closed stage-4 report gate: compare real samples, not fabricated claims.

WAN readiness requires 3 separate UTC days and >=5 good samples per day,
matching controlled scenarios, no integrity errors, success>=99%, and no
material regression vs legacy. Lab results validate the harness only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import statistics

import compare_transports as metrics

MIN_DAYS = 3
MIN_DAILY_SAMPLES = 5


def load_report(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != 1 or data.get("kind") != "foxtunnel-stage4-field":
        raise ValueError("unknown stage-4 report schema")
    if data.get("environment") not in ("lab", "wan"):
        raise ValueError("unknown measurement environment")
    if data.get("mode") not in ("tcp", "udp") or not isinstance(data.get("samples"), list):
        raise ValueError("invalid probe mode/samples")
    if not isinstance(data.get("configuration"), dict):
        raise ValueError("missing measurement configuration")
    dt.datetime.fromisoformat(data["created_at_utc"])
    return data


def gate_report_set(base: list[dict], candidate: list[dict],
                    base_label: str, candidate_label: str,
                    require_wan: bool = True) -> dict:
    if not base or not candidate:
        raise ValueError("both baseline and candidate files are required")
    if base_label == candidate_label:
        raise ValueError("baseline and candidate must be distinct labels")
    reports = base + candidate
    first = base[0]
    mode, scenario = first["mode"], first["scenario"]
    environment = first["environment"]
    config = first["configuration"]
    for report in reports:
        if report["mode"] != mode or report["scenario"] != scenario:
            raise ValueError("scenario/mode mismatch")
        if report["environment"] != environment:
            raise ValueError("cannot mix lab and WAN reports")
        if report["configuration"].get("bytes_per_flow") != config.get("bytes_per_flow"):
            raise ValueError("different transfer size; compare like with like")
        if report["configuration"].get("distinct_target_count") != config.get("distinct_target_count"):
            raise ValueError("different target count")
        if require_wan and (environment != "wan" or
                            report.get("external_topology") != "user-attested-unverified"):
            raise ValueError("release gate needs user-attested WAN observations")
    rows_by_label = {}
    days_by_label = {}
    issues = []
    for label, source in ((base_label, base), (candidate_label, candidate)):
        rows = []
        daily = {}
        for report in source:
            day = dt.datetime.fromisoformat(report["created_at_utc"]).date().isoformat()
            selected = [r for r in report["samples"] if r.get("proxy") == label]
            daily[day] = daily.get(day, 0) + sum(1 for row in selected if row.get("ok") is True)
            for item in selected:
                # Reject spoofed or unbounded metrics before computing a
                # seemingly green comparison report.
                if not isinstance(item.get("ok"), bool):
                    raise ValueError("sample has no boolean success flag")
                if item["ok"]:
                    if mode == "tcp":
                        fields = ("completion_ms", "payload_mbps")
                    else:
                        fields = ("rtt_ms",)
                    if any(not isinstance(item.get(f), (int, float)) or
                           isinstance(item.get(f), bool) or
                           not 0 < item[f] < 1e12 for f in fields):
                        raise ValueError("successful sample lacks valid numeric metrics")
                rows.append(item)
        if not rows:
            raise ValueError("missing samples for " + label)
        if require_wan:
            if len(daily) < MIN_DAYS:
                issues.append(label + ": less than 3 separate measurement days")
            if any(value < MIN_DAILY_SAMPLES for value in daily.values()):
                issues.append(label + ": fewer than 5 samples on a measured day")
        rows_by_label[label] = rows
        days_by_label[label] = daily
    if require_wan and set(days_by_label[base_label]) != set(days_by_label[candidate_label]):
        issues.append("baseline/candidate measurement UTC days differ")
    baseline = metrics_of(rows_by_label[base_label], mode)
    challenger = metrics_of(rows_by_label[candidate_label], mode)

    for label, m in ((base_label, baseline), (candidate_label, challenger)):
        if m["success_pct"] < 99:
            issues.append(label + ": successful exchanges below 99%")
        if any(r.get("error_category") in ("ValueError", "IntegrityError")
               for r in rows_by_label[label]):
            issues.append(label + ": possible payload integrity failure")
    if mode == "tcp":
        if scenario.lower().find("small") >= 0 or config.get("bytes_per_flow", 0) <= 4096:
            if challenger["latency_p95_ms"] > baseline["latency_p95_ms"] * 1.1:
                issues.append("p95 completion latency regressed >10%")
        else:
            if challenger["median_mbps"] < baseline["median_mbps"] * .9:
                issues.append("median TCP goodput regressed >10%")
    else:
        if challenger["latency_p95_ms"] > baseline["latency_p95_ms"] * 1.1:
            issues.append("UDP p95 RTT regressed >10%")
        if challenger["loss_pct"] > baseline["loss_pct"] + 1:
            issues.append("UDP loss increased by >1 percentage point")

    return {"schema": 1, "mode": mode, "scenario": scenario,
            "environment": environment, "wan_verified_by_tool": False,
            "ready_for_release_gate": bool(require_wan and not issues),
            "passed": not issues, "issues": issues,
            "baseline": baseline, "candidate": challenger,
            "baseline_days": days_by_label[base_label],
            "candidate_days": days_by_label[candidate_label]}


def metrics_of(rows: list[dict], mode: str) -> dict:
    ok = [r for r in rows if r["ok"]]
    if not ok:
        raise ValueError("cannot compare experiments with no successful samples")
    times = [r["rtt_ms"] if mode == "udp" else r["completion_ms"] for r in ok]
    pct = 100 * len(ok) / len(rows)
    result = {"attempted": len(rows), "successful": len(ok),
              "success_pct": round(pct, 3),
              "latency_p50_ms": metrics.percentile(times, .5),
              "latency_p95_ms": metrics.percentile(times, .95),
              "latency_p99_ms": metrics.percentile(times, .99)}
    if mode == "tcp":
        result["median_mbps"] = round(statistics.median(r["payload_mbps"] for r in ok), 3)
    else:
        result["loss_pct"] = round(100 * (len(rows) - len(ok)) / len(rows), 3)
        result["jitter_mean_abs_delta_ms"] = round(statistics.mean(
            abs(y - x) for x, y in zip(times, times[1:])), 3) if len(times) > 1 else None
    return result


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=Path, action="append", required=True)
    p.add_argument("--candidate", type=Path, action="append", required=True)
    p.add_argument("--baseline-label", default="legacy")
    p.add_argument("--candidate-label", default="adaptive")
    p.add_argument("--allow-lab", action="store_true",
                   help="for unit-test/laboratory checks ONLY; never release-ready")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        if a.out.exists() or not a.out.parent.is_dir():
            raise ValueError("output already exists or parent directory missing")
        left = [load_report(path) for path in a.baseline]
        right = [load_report(path) for path in a.candidate]
        result = gate_report_set(left, right, a.baseline_label, a.candidate_label,
                                 require_wan=not a.allow_lab)
        with a.out.open("x", encoding="utf-8") as out:
            json.dump(result, out, indent=2)
            out.write("\n")
    except (ValueError, KeyError, OSError, TypeError) as exc:
        p.error(str(exc))
    print("stage4 gate: " + ("PASS" if result["passed"] else "FAIL"))
    for issue in result["issues"]:
        print(" - " + issue)
    if a.allow_lab:
        print("LAB ONLY: not release-ready")
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
