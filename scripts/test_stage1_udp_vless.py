"""Offline UDP-vs-VLESS harness tests: only loopback mock SOCKS5 services."""
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

import stage1_udp_vless as runner
import stage1_udp_vless_gate as gate
from test_bond_stage4 import LocalUDPSOCKS


def fixture(day: int, fox_rtt: float = 10.5, vless_rtt: float = 10.0) -> dict:
    rows = []
    for label, rtt in (("fox", fox_rtt), ("vless", vless_rtt)):
        for i in range(1, 21):
            rows.append({"proxy": label, "round": i, "flow": 1,
                         "ok": True, "rtt_ms": rtt, "error_category": None,
                         "integrity_failure": False})
    return {
        "schema": 1, "kind": "foxtunnel-vless-stage1-udp",
        "created_at_utc": f"2026-10-{day:02}T11:00:00+00:00",
        "environment": "wan", "wan_attested_by_operator": True,
        "configuration": {"rounds": 20, "parallel": 1, "warmup": 1,
                          "timeout_seconds": 2, "distinct_target_count": 1,
                          "fox_transport": "h2-connect",
                          "vless_transport": "reality-vision"},
        "samples": rows,
    }


class UDPStage1Tests(unittest.TestCase):
    def test_end_to_end_over_two_real_socket_mocks(self):
        with LocalUDPSOCKS() as fox, LocalUDPSOCKS() as vless:
            with tempfile.TemporaryDirectory() as d:
                out = Path(d) / "udp.json"
                argv = ["--fox-socks", f"{fox.host}:{fox.port}",
                        "--vless-socks", f"{vless.host}:{vless.port}",
                        "--target", "127.0.0.1:9001",
                        "--environment", "lab", "--rounds", "20",
                        "--parallel", "1", "--warmup", "1",
                        "--timeout", "1", "--out", str(out)]
                self.assertEqual(runner.main(argv), 0)
                result = json.loads(out.read_text())
                self.assertEqual(result["schema"], 1)
                self.assertEqual(len(result["samples"]), 40)
                self.assertTrue(all(x["ok"] and x["rtt_ms"] > 0 for x in result["samples"]))
                self.assertFalse(result["wan_verified_by_tool"])
                self.assertNotIn(f"{fox.host}:{fox.port}", out.read_text())
                self.assertNotIn(f"{vless.host}:{vless.port}", out.read_text())
                self.assertNotIn("127.0.0.1:9001", out.read_text())
                self.assertEqual(runner.main(argv), 2)  # exclusive output

    def test_pass_three_wan_days_descriptive_jitter(self):
        reports = [fixture(x) for x in (18, 19, 20)]
        result = gate.evaluate(reports)
        self.assertTrue(result["passed"], result["issues"])
        self.assertEqual(result["days_observed"], 3)
        self.assertEqual(result["measurements"][0]["fox"]["rtt_p95_ms"], 10.5)
        self.assertFalse(result["wan_verified_by_tool"])

    def test_fails_slower_rtt_and_failures(self):
        reports = [fixture(x) for x in (18, 19, 20)]
        for r in reports[1]["samples"]:
            if r["proxy"] == "fox":
                r["rtt_ms"] = 20
        verdict = gate.evaluate(reports)
        self.assertIn("FoxTunnel UDP echo p95 above 110% VLESS", verdict["issues"])
        reports = [fixture(x) for x in (18, 19, 20)]
        fox = next(r for r in reports[0]["samples"] if r["proxy"] == "fox")
        fox.update(ok=False, rtt_ms=None, error_category="TimeoutError")
        verdict = gate.evaluate(reports)
        self.assertIn("UDP echo success rate below 99%", verdict["issues"])
        self.assertIn("FoxTunnel UDP failed-echo rate above VLESS by >1 pp", verdict["issues"])

    def test_fails_integrity_mismatch(self):
        reports = [fixture(x) for x in (18, 19, 20)]
        reports[1]["samples"][0].update(
            ok=False, rtt_ms=None, error_category="ValueError", integrity_failure=True)
        self.assertIn("UDP echo integrity error", gate.evaluate(reports)["issues"])
        result = runner.sanitize({"proxy": "fox", "round": 1, "flow": 1,
                                  "ok": False, "rtt_ms": None,
                                  "error_category": "ValueError"})
        self.assertTrue(result["integrity_failure"])

    def test_gate_rejects_missing_invalid_or_mixed_samples(self):
        reports = [fixture(x) for x in (18, 19, 20)]
        reports[0]["samples"][1]["round"] = 1
        with self.assertRaises(ValueError):
            gate.evaluate(reports)
        reports = [fixture(x) for x in (18, 19, 20)]
        reports[0]["samples"][0]["rtt_ms"] = float("nan")
        with self.assertRaises(ValueError):
            gate.evaluate(reports)
        reports = [fixture(x) for x in (18, 19, 20)]
        reports[1]["configuration"]["fox_transport"] = "h3-post"
        with self.assertRaisesRegex(ValueError, "mixed"):
            gate.evaluate(reports)
        reports = [fixture(x) for x in (18, 19, 20)]
        reports[0]["samples"][0]["proxy"] = "unknown"
        with self.assertRaisesRegex(ValueError, "unexpected"):
            gate.evaluate(reports)

    def test_wan_requires_confirmed_topology_and_modes(self):
        with tempfile.TemporaryDirectory() as d:
            argv = ["--fox-socks", "127.0.0.1:1080",
                    "--vless-socks", "127.0.0.1:1081",
                    "--target", "127.0.0.1:9001",
                    "--rounds", "20", "--environment", "wan",
                    "--out", str(Path(d) / "report.json")]
            with self.assertRaisesRegex(ValueError, "WAN"):
                runner.validate(runner.parser().parse_args(argv))
            a = runner.parser().parse_args(
                argv + ["--confirm-independent-vds", "--fox-transport", "h2-connect",
                        "--vless-transport", "reality-vision"])
            runner.validate(a)
            a.environment = "lab"
            with self.assertRaises(ValueError):
                runner.validate(a)

    def test_three_distinct_days_required(self):
        reports = [fixture(x) for x in (18, 18, 20)]
        self.assertFalse(gate.evaluate(reports)["passed"])

    def test_gate_rejects_lab_label_even_when_echo_is_healthy(self):
        reports = [fixture(x) for x in (18, 19, 20)]
        reports[1]["environment"] = "lab"
        self.assertIn("independent WAN topology not operator-attested",
                      gate.evaluate(reports)["issues"])


if __name__ == "__main__":
    unittest.main()
