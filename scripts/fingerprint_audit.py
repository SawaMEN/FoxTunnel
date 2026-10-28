#!/usr/bin/env python3
"""Evidence-only Firefox / VetroffProxy / NaiveProxy TLS/H2 and QUIC/H3 audit.

Missing measurements never count as matches. There is no similarity score.
Reports are exclusive-created owner-only files without source paths/secrets.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sys

TLS_FIELDS = (
    "hello.record_version", "hello.legacy_version", "hello.cipher_suites",
    "hello.extensions", "hello.supported_groups", "hello.ec_point_formats",
    "hello.supported_versions", "hello.signature_algorithms",
    "hello.key_share_groups", "hello.alpn", "hello.sni_present",
    "hello.ja3", "negotiated_alpn",
)
H2_FIELDS = ("initial_h2_settings", "initial_connection_window_updates")
H3_FIELDS = (
    "quic.version", "quic.tls_alpn", "quic.initial_datagram_size",
    "quic.transport_parameters", "h3.settings",
)
SETTING_IDS = {1: "header_table", 2: "enable_push", 4: "stream_window",
               5: "frame_size", 6: "header_list_size"}
MAX_INPUT = 4 * 1024 * 1024
ABSENT = object()


def ja3_expected(hello: dict) -> str:
    """Recompute the JA3 compatibility string without payload or SNI."""
    def uints(name: str, *, required: bool = False) -> list[int]:
        value = hello.get(name)
        if value is None and not required:
            return []
        if (not isinstance(value, list) or
                any(type(item) is not int or item < 0 or item > 65535
                    for item in value)):
            raise ValueError("invalid captured JA3 vector")
        return value

    legacy = hello.get("legacy_version")
    if type(legacy) is not int or not 0 <= legacy <= 65535:
        raise ValueError("invalid TLS legacy version")
    cipher = uints("cipher_suites", required=True)
    extensions = uints("extensions", required=True)
    groups = uints("supported_groups")
    points = uints("ec_point_formats")
    if not cipher or not extensions:
        raise ValueError("TLS JA3 cipher/extension evidence missing")

    def grease(value: int) -> bool:
        return (value >> 8) == (value & 0xff) and (value & 0x0f) == 0x0a

    def vector(values: list[int], filter_grease: bool) -> str:
        return "-".join(str(v) for v in values
                        if not filter_grease or not grease(v))

    return ",".join((str(legacy), vector(cipher, True),
                     vector(extensions, True), vector(groups, True),
                     vector(points, False)))


def read_profile(path: Path, kind: str) -> tuple[dict, str]:
    if not path.is_file() or path.stat().st_size > MAX_INPUT:
        raise ValueError("capture file missing or exceeds 4 MiB")
    data = path.read_bytes()
    return decode_profile(data, kind), hashlib.sha256(data).hexdigest()


def decode_profile(data: bytes, kind: str) -> dict:
    """Validate one already-snapshotted observation without rereading its path."""
    raw = json.loads(data)
    if not isinstance(raw, dict) or raw.get("schema") != 1:
        raise ValueError("unsupported observation schema")
    if kind == "tls_h2":
        if not isinstance(raw.get("hello"), dict):
            raise ValueError("missing TLS ClientHello metadata")
        hello = raw["hello"]
        expected = ja3_expected(hello)
        if hello.get("ja3") != expected or hello.get("ja3_md5") != hashlib.md5(
                expected.encode("ascii")).hexdigest():
            raise ValueError("TLS JA3 incompatible with captured handshake metadata")
        if not isinstance(raw.get("initial_h2_settings"), list) or not raw["initial_h2_settings"]:
            raise ValueError("missing initial H2 SETTINGS; a partial capture is not H2 evidence")
        for item in raw["initial_h2_settings"]:
            if (not isinstance(item, dict) or type(item.get("id")) is not int
                    or type(item.get("value")) is not int or
                    not 1 <= item["id"] <= 65535 or
                    not 0 <= item["value"] <= 0xffffffff):
                raise ValueError("malformed initial H2 SETTINGS")
        if len({x["id"] for x in raw["initial_h2_settings"]}) != len(raw["initial_h2_settings"]):
            raise ValueError("duplicate H2 SETTINGS identifier")
        if raw.get("dropped_frames", 0) or raw.get("dropped_records", 0):
            raise ValueError("truncated TLS/H2 capture")
    elif kind == "h3_quic":
        if raw.get("kind") != "h3-quic-observation":
            raise ValueError("H3/QUIC requires endpoint-decoded evidence")
        if not isinstance(raw.get("quic"), dict) or not isinstance(raw.get("h3"), dict):
            raise ValueError("missing QUIC/H3 observations")
        q, h3 = raw["quic"], raw["h3"]
        if (type(q.get("version")) is not int or q["version"] <= 0
                or not isinstance(q.get("tls_alpn"), str)
                or not q["tls_alpn"]
                or type(q.get("initial_datagram_size")) is not int
                or not 1 <= q["initial_datagram_size"] <= 65527):
            raise ValueError("QUIC version, ALPN and datagram size require actual capture")
        if (not isinstance(q.get("transport_parameters"), list)
                or not q["transport_parameters"]
                or not isinstance(h3.get("settings"), list)
                or not h3["settings"]):
            raise ValueError("missing decoded QUIC transport parameters or H3 SETTINGS")
        for entries in (q["transport_parameters"], h3["settings"]):
            if (any(not isinstance(item, dict) or
                    type(item.get("id")) is not int or
                    not 0 <= item["id"] <= (1 << 62) - 1 or
                    "value" not in item
                    for item in entries) or
                    len({item["id"] for item in entries}) != len(entries)):
                raise ValueError("invalid or duplicated endpoint-decoded QUIC/H3 identifiers")
        if (raw.get("capture_method") != "endpoint"
                or not isinstance(raw.get("capture_scenario"), str)
                or not raw["capture_scenario"].strip()):
            raise ValueError("capture provenance must identify endpoint decoding and scenario")
    else:
        raise ValueError("unsupported observation type")
    return raw


def path_value(data: dict, dotted: str):
    node = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return ABSENT
        node = node[part]
    return ABSENT if node is None else node


def field_row(field: str, reference: dict | None, candidate: dict | None) -> dict:
    if reference is None or candidate is None:
        return {"field": field, "status": "not_measured"}
    left, right = path_value(reference, field), path_value(candidate, field)
    if left is ABSENT or right is ABSENT:
        return {"field": field, "status": "not_observed",
                "reference_observed": left is not ABSENT,
                "candidate_observed": right is not ABSENT}
    return {"field": field, "status": "equal" if left == right else "different",
            "reference": left, "candidate": right}


def h2_setting_rows(reference: dict | None, candidate: dict | None) -> list[dict]:
    if reference is None or candidate is None:
        return [{"field": "h2.settings." + name, "status": "not_measured"}
                for name in SETTING_IDS.values()]
    a = {x["id"]: x["value"] for x in reference["initial_h2_settings"]}
    b = {x["id"]: x["value"] for x in candidate["initial_h2_settings"]}
    result = []
    for setting_id, name in SETTING_IDS.items():
        av, bv = a.get(setting_id, ABSENT), b.get(setting_id, ABSENT)
        result.append({
            "field": "h2.settings." + name,
            "status": "equal" if av == bv else "different",
            "reference": "absent" if av is ABSENT else av,
            "candidate": "absent" if bv is ABSENT else bv,
        })
    return result


def compare(a_tls: dict | None, b_tls: dict | None,
            a_quic: dict | None, b_quic: dict | None) -> dict:
    tls_rows = [field_row(f, a_tls, b_tls) for f in TLS_FIELDS]
    h2_rows = [field_row(f, a_tls, b_tls) for f in H2_FIELDS]
    h2_rows.extend(h2_setting_rows(a_tls, b_tls))
    h3_rows = [field_row(f, a_quic, b_quic) for f in H3_FIELDS]
    def count(rows):
        return {state: sum(row["status"] == state for row in rows)
                for state in ("equal", "different", "not_observed", "not_measured")}
    return {
        "tls": {"counts": count(tls_rows), "checks": tls_rows},
        "http2": {"counts": count(h2_rows), "checks": h2_rows},
        "quic_http3": {"counts": count(h3_rows), "checks": h3_rows},
        "metadata_equal": (
            a_tls is not None and b_tls is not None
            and all(row["status"] == "equal" for row in tls_rows + h2_rows)
            and a_quic is not None and b_quic is not None
            and all(row["status"] == "equal" for row in h3_rows)
        ),
    }


def report(args) -> dict:
    tls, quic, digests = {}, {}, {}
    for name in ("firefox", "vetroffproxy", "naive"):
        path = getattr(args, name)
        qpath = getattr(args, name + "_quic")
        tls[name], quic[name] = None, None
        digests[name] = {"tls_h2": None, "quic_h3": None}
        if path is not None:
            tls[name], digests[name]["tls_h2"] = read_profile(path, "tls_h2")
        if qpath is not None:
            quic[name], digests[name]["quic_h3"] = read_profile(qpath, "h3_quic")
    comparisons = {
        name: compare(tls["firefox"], tls[name], quic["firefox"], quic[name])
        for name in ("vetroffproxy", "naive")
    }
    return {
        "schema": 1, "kind": "fox-stage10-fingerprint-audit",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "subjects": {
            name: {"tls_h2_observed": tls[name] is not None,
                   "quic_h3_observed": quic[name] is not None,
                   "sha256_of_capture": digests[name]}
            for name in ("firefox", "vetroffproxy", "naive")
        },
        "comparisons_to_firefox": comparisons,
        "scenario_equivalence_verified": False,
        "all_three_and_both_protocols_measured": all(
            tls[name] is not None and quic[name] is not None
            for name in ("firefox", "vetroffproxy", "naive")
        ),
        "limitations": [
            "Source captures may differ in version, workload, time, route and server.",
            "Absent NaiveProxy/QUIC captures are unmeasured, never inferred.",
            "Matching any subset, JA3 or TLS record lengths does not establish indistinguishability.",
            "QUIC parameters and H3 settings require endpoint-assisted decoding.",
            "H2 SETTINGS are encrypted on-path.",
            "This is not evidence of DPI or TSPU bypass.",
            "No raw request data, hostnames, secrets or capture paths are serialized.",
        ],
    }


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--firefox", required=True, type=Path)
    p.add_argument("--vetroffproxy", required=True, type=Path)
    p.add_argument("--naive", type=Path, help="optional actually captured NaiveProxy TLS/H2 observation")
    for name in ("firefox", "vetroffproxy", "naive"):
        p.add_argument("--" + name + "-quic", type=Path,
                       help="optional independent endpoint-decoded QUIC/H3 observation")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--require-complete", action="store_true",
                   help="return error unless all three clients have H2 and H3 observations")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.out.exists() or not args.out.parent.is_dir():
            raise ValueError("destination already exists or parent directory missing")
        result = report(args)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(result, output, indent=2, sort_keys=True)
            output.write("\n")
        for name, comp in result["comparisons_to_firefox"].items():
            print(name, "vs Firefox:",
                  "; ".join(label + "=" + str(comp[label]["counts"])
                            for label in ("tls", "http2", "quic_http3")))
        print("coverage complete:", result["all_three_and_both_protocols_measured"])
        print("report:", args.out)
        return 2 if args.require_complete and not result["all_three_and_both_protocols_measured"] else 0
    except (OSError, ValueError, TypeError):
        print("invalid or incomplete fingerprint evidence; no complete comparison", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
