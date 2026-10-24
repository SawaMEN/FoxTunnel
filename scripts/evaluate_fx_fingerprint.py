#!/usr/bin/env python3
"""Classify FoxTunnel/Firefox wire mismatches using Firefox-vs-Firefox controls.

This is a regression detector, NOT a claim of browser or DPI indistinguishability.
A difference naturally observed in Firefox controls is *inconclusive*, not equal.
"""
import argparse
import json
import os
from pathlib import Path


MODES = ("h2-connect", "h3-connect")


def _rows(observation):
    seen = {}
    for row in observation.get("checks", []):
        field = row.get("field")
        if not isinstance(field, str) or not field or field in seen:
            raise ValueError("invalid or duplicate comparison field")
        if row.get("status") not in ("equal", "different"):
            raise ValueError("invalid comparison status")
        if (row["reference"] == row["candidate"]) != (row["status"] == "equal"):
            raise ValueError("inconsistent comparison status")
        seen[field] = row
    if not seen:
        raise ValueError("empty comparison")
    return seen


def evaluate(candidate, control, minimum=3):
    if candidate.get("schema") != 1 or candidate.get("kind") != "necko-firefox-comparison-report":
        raise ValueError("wrong candidate report")
    if control.get("schema") != 1 or control.get("kind") != "firefox-self-comparison-report":
        raise ValueError("wrong Firefox self-control report")
    if candidate.get("runtime_sha256") != control.get("runtime_sha256") or (
        candidate.get("source_sha256") != control.get("source_sha256")):
        raise ValueError("different Firefox runtime or source lock")
    if not isinstance(minimum, int) or minimum < 1:
        raise ValueError("invalid minimum repetitions")
    out = {"schema": 1, "kind": "fx-firefox-regression-audit",
           "scope": "Raw CONNECT on one pinned Gecko runtime; not ordinary Firefox navigation",
           "runtime_sha256": candidate["runtime_sha256"],
           "source_sha256": candidate["source_sha256"],
           "results": {}, "unexpected_differences": 0, "variable_differences": 0,
           "sporadic_differences": 0,
           "limitations": [
               "Firefox-to-Firefox variation is inconclusive, not proof of similarity.",
               "Three or more lab observations cannot establish distributional equivalence.",
               "An isolated H2 frame or HPACK mismatch is recorded as sporadic; at least two-thirds repeated non-control mismatches are required to block CI.",
               "No claims about ordinary browsing, traffic timing, payload shapes or DPI."
           ]}
    for mode in MODES:
        refs = [ob for ob in control.get("observations", []) if ob.get("transport") == mode]
        trials = [ob for ob in candidate.get("observations", []) if ob.get("transport") == mode]
        if len(refs) < minimum or len(trials) < minimum:
            raise ValueError("insufficient matched repetitions for " + mode)
        field_set = set(_rows(refs[0]))
        volatile = set()
        samples = {name: set() for name in field_set}
        for ob in refs:
            rows = _rows(ob)
            if set(rows) != field_set:
                raise ValueError("inconsistent Firefox self-control fields")
            for field, row in rows.items():
                if row["status"] == "different":
                    volatile.add(field)
                samples[field].add(json.dumps(row["reference"], sort_keys=True))
                samples[field].add(json.dumps(row["candidate"], sort_keys=True))
        volatile.update(field for field, values in samples.items() if len(values) > 1)
        unexpected, variable, sporadic = set(), set(), set()
        candidate_mismatches = {field: 0 for field in field_set}
        control_mismatches = {field: 0 for field in field_set}
        for ob in refs:
            for field, row in _rows(ob).items():
                control_mismatches[field] += row["status"] == "different"
        for ob in trials:
            rows = _rows(ob)
            if set(rows) != field_set:
                raise ValueError("candidate and Firefox control fields differ")
            for field, row in rows.items():
                if row["status"] == "different":
                    candidate_mismatches[field] += 1
        # A single mismatch in three repetitions can arise from HPACK state or
        # SETTINGS ACK scheduling, including runs where the small Firefox self
        # sample happens not to capture it. Preserve the field and frequency.
        # Fail closed only on repeated differences outside the self controls.
        threshold = max(2, (len(trials) * 2 + 2) // 3)
        for field, count in candidate_mismatches.items():
            if not count:
                continue
            if field in volatile:
                variable.add(field)
            elif count >= threshold:
                unexpected.add(field)
            else:
                sporadic.add(field)
        # Persistent mismatches against naturally variable Firefox fields merit
        # investigation, but cannot be promoted to a "definite" mismatch.
        persistent = sorted(field for field in variable
                            if candidate_mismatches[field] == len(trials)
                            and control_mismatches[field] < len(refs))
        out["results"][mode] = {
            "candidate_repetitions": len(trials),
            "control_repetitions": len(refs),
            "control_variable_fields": sorted(volatile),
            "unexpected_fields": sorted(unexpected),
            "sporadic_fields": sorted(sporadic),
            "inconclusive_fields": sorted(variable),
            "persistent_mismatch_threshold": threshold,
            "persistent_under_variable_control": persistent,
            "mismatch_frequencies": [
                {"field": field,
                 "candidate": candidate_mismatches[field],
                 "candidate_total": len(trials),
                 "firefox_self": control_mismatches[field],
                 "firefox_self_total": len(refs)}
                for field in sorted(field_set)
                if candidate_mismatches[field] or control_mismatches[field]],
        }
        out["unexpected_differences"] += len(unexpected)
        out["variable_differences"] += len(variable)
        out["sporadic_differences"] += len(sporadic)
    out["status"] = ("regression-detected" if out["unexpected_differences"] else
                     "inconclusive" if out["variable_differences"] or out["sporadic_differences"] else
                     "no-differences-in-recorded-fields")
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--minimum-repetitions", type=int, default=3)
    parser.add_argument("--enforce", action="store_true",
                        help="Exit nonzero for differences outside Firefox controls")
    args = parser.parse_args()
    for filename in (args.candidate, args.control):
        if filename.stat().st_size > 16 << 20:
            parser.error("oversized comparison report")
    result = evaluate(json.loads(args.candidate.read_text()),
                      json.loads(args.control.read_text()), args.minimum_repetitions)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    print("FX fingerprint audit:", result["status"])
    for mode, row in result["results"].items():
        print(mode, "unexpected:", ", ".join(row["unexpected_fields"]) or "none",
              "inconclusive:", ", ".join(row["inconclusive_fields"]) or "none",
              "sporadic:", ", ".join(row["sporadic_fields"]) or "none")
    if args.enforce and result["unexpected_differences"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
