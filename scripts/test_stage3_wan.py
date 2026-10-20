"""No-network test fixtures for three-way Stage 3 WAN reporting and release gate."""
from __future__ import annotations

import copy
import json
import tempfile
import threading
import unittest
from pathlib import Path

import stage3_wan as runner
import stage3_wan_gate as gate
from test_compare_transports import SOCKSHandler, SOCKSServer

BASELINE = "23d3ba78dcf77fb810a26ef27b1a30133490ce86"
CANDIDATE = "c783462c57fb261acc1201c9277e5a9bd44935ed"


def fake_report(day: int, scenario: str) -> dict:
    size = 1024 if scenario == "small" else 32 << 20
    rows = []
    for label in runner.LABELS:
        speed = 110.0 if label == "candidate" else 100.0
        for i in range(1, 31):
            rows.append({
                "proxy": label, "round": i, "flow": 1, "ok": True,
                "connect_ms": 10.0, "transfer_ms": 5.0, "completion_ms": 15.0,
                "payload_mbps": speed, "error_category": None,
                "integrity_failure": False,
            })
    return {
        "schema": 1, "kind": "foxtunnel-stage3-3way",
        "created_at_utc": f"2026-10-{day:02d}T10:00:00+00:00",
        "scenario": scenario, "environment": "wan",
        "wan_attested_by_operator": True, "wan_verified_by_tool": False,
        "configuration": {
            "baseline_sha": BASELINE, "candidate_sha": CANDIDATE,
            "fox_transport": "h2-connect", "vless_transport": "reality-vision",
            "bytes_per_flow": size, "rounds": 30, "parallel": 1,
            "warmup": 2, "timeout_seconds": 30,
        },
        "samples": rows,
        "resources": {
            label: {"cpu_percent_one_core": 8 if label == "candidate" else 10,
                    "rss_peak_mib": 48 if label == "candidate" else 55}
            for label in runner.LABELS
        },
    }


def reports():
    return [fake_report(day, scenario)
            for day in (18, 19, 20) for scenario in ("small", "bulk")]


class Stage3WanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = [SOCKSServer(("127.0.0.1", 0), SOCKSHandler) for _ in range(3)]
        cls.threads = [threading.Thread(target=server.serve_forever, daemon=True)
                       for server in cls.servers]
        for thread in cls.threads:
            thread.start()

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(3)

    def args(self, filename: Path, scenario="small", *, environment="lab"):
        params = [
            "--target", "echo.private.example:9000",
            "--baseline-sha", BASELINE, "--candidate-sha", CANDIDATE,
            "--fox-transport", "h2-connect", "--vless-transport", "reality-vision",
            "--scenario", scenario, "--environment", environment,
            "--rounds", "3", "--parallel", "2", "--warmup", "0",
            "--bytes", "4096", "--out", str(filename),
        ]
        for label, server in zip(runner.LABELS, self.servers):
            params += [f"--{label}-socks", f"127.0.0.1:{server.server_address[1]}"]
        return params

    def test_lab_end_to_end_sanitized_all_three_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "three.json"
            argv = self.args(output)
            self.assertEqual(runner.main(argv), 0)
            report = gate.load(output)
            self.assertEqual(len(report["samples"]), 18)
            self.assertEqual({s["proxy"] for s in report["samples"]}, set(runner.LABELS))
            self.assertFalse(report["wan_attested_by_operator"])
            self.assertFalse(report["wan_verified_by_tool"])
            self.assertIsNone(report["resources"])
            serialized = output.read_text()
            self.assertNotIn("echo.private.example", serialized)
            self.assertNotIn("127.0.0.1", serialized)
            self.assertNotIn("private-", serialized)
            self.assertEqual(runner.main(argv), 2)

    def test_three_way_socks_identity_and_revision_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            a = runner.parser().parse_args(self.args(Path(tmp) / "report.json"))
            self.assertEqual(runner.validate(a), 4096)
            a.candidate_sha = BASELINE
            with self.assertRaisesRegex(ValueError, "revision"):
                runner.validate(a)
            a.candidate_sha = CANDIDATE
            a.vless_socks = a.baseline_socks
            with self.assertRaisesRegex(ValueError, "distinct"):
                runner.validate(a)
            a.vless_socks = f"127.0.0.1:{self.servers[2].server_address[1]}"
            a.confirm_independent_vds = True
            with self.assertRaisesRegex(ValueError, "attestation"):
                runner.validate(a)
            a.confirm_independent_vds = False
            a.baseline_pid = 1
            with self.assertRaisesRegex(ValueError, "three"):
                runner.validate(a)

    def test_exactly_three_matched_wan_days_pass_conditionally(self):
        data = reports()
        result = gate.evaluate(data)
        self.assertTrue(result["passed"], result["issues"])
        self.assertEqual(result["observed_utc_days"], {"small": 3, "bulk": 3})
        self.assertFalse(result["wan_verified_by_tool"])
        self.assertEqual(result["baseline_sha"], BASELINE)
        self.assertEqual(len(result["measurements"]), 6)
        self.assertEqual(result["measurements"][0]["candidate_vs"]["baseline"]["goodput_ratio"], 1.1)

    def test_gate_fails_lab_missing_days_and_missing_resource(self):
        doc = reports()
        doc[0]["environment"] = "lab"
        doc[0]["wan_attested_by_operator"] = False
        doc[3]["resources"] = None
        result = gate.evaluate(doc)
        self.assertFalse(result["passed"])
        self.assertIn("operator WAN attestation missing", result["issues"])
        self.assertIn("bulk CPU/RSS monitoring missing for three clients", result["issues"])
        result = gate.evaluate(reports()[:-2])
        self.assertIn("three distinct UTC days of small required", result["issues"])
        self.assertIn("three distinct UTC days of bulk required", result["issues"])

    def test_gate_detects_slow_or_corrupt_candidate(self):
        doc = reports()
        for row in doc[1]["samples"]:
            if row["proxy"] == "candidate":
                row["payload_mbps"] = 70.0
                row["connect_ms"] = 17.0
                row["completion_ms"] = 22.0
        result = gate.evaluate(doc)
        self.assertFalse(result["passed"])
        self.assertIn("candidate bulk median below 90% baseline", result["issues"])
        self.assertIn("candidate CONNECT p95 above 110% vless", result["issues"])
        doc = reports()
        doc[0]["samples"][30]["integrity_failure"] = True
        doc[0]["samples"][30]["ok"] = False
        self.assertIn("echo integrity mismatch", gate.evaluate(doc)["issues"])

    def test_gate_rejects_malformed_samples_duplicate_days_and_untruthful_attestation(self):
        doc = reports()
        doc[0]["samples"][0]["round"] = 2
        with self.assertRaisesRegex(ValueError, "duplicate"):
            gate.evaluate(doc)
        doc = reports()
        doc[0]["samples"][0]["completion_ms"] = 0.1
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            gate.evaluate(doc)
        doc = reports()
        doc[0]["wan_verified_by_tool"] = True
        with self.assertRaisesRegex(ValueError, "untruthful"):
            gate.evaluate(doc)
        doc = reports()
        with self.assertRaisesRegex(ValueError, "duplicate UTC day"):
            gate.evaluate(doc + [copy.deepcopy(doc[0])])
        doc = reports()
        doc[0]["configuration"]["candidate_sha"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "mixed"):
            gate.evaluate(doc)
        doc = reports()
        doc[1]["samples"].append(copy.deepcopy(doc[1]["samples"][-1]))
        with self.assertRaisesRegex(ValueError, "population"):
            gate.evaluate(doc)

    def test_gate_fails_low_sample_size_and_bad_input(self):
        doc = reports()
        doc[0]["configuration"]["rounds"] = 2
        with self.assertRaisesRegex(ValueError, "undersampled"):
            gate.evaluate(doc)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "fake.json"
            p.write_text('{"schema":99,"kind":"foxtunnel-stage3-3way"}')
            with self.assertRaisesRegex(ValueError, "not a stage3"):
                gate.load(p)


if __name__ == "__main__":
    unittest.main()
