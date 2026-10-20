"""Offline tests for the redacted Stage 1 FoxTunnel vs Xray/VLESS benchmark."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

import stage1_vless as runner
import stage1_vless_gate as gate
from test_compare_transports import SOCKSHandler, SOCKSServer


def fake_report(day: int, scenario="small") -> dict:
    samples = []
    for label, speed in (("fox", 95.0), ("vless", 100.0)):
        for i in range(1, 7):
            samples.append({"proxy": label, "round": i, "flow": 1, "ok": True,
                            "connect_ms": 10.0, "transfer_ms": 5.0, "completion_ms": 15.0,
                            "payload_mbps": speed,
                            "error_category": None, "integrity_failure": False})
    return {"schema": 2, "kind": "foxtunnel-vless-stage1",
            "created_at_utc": f"2026-10-{day:02d}T10:00:00+00:00",
            "scenario": scenario, "environment": "wan",
            "wan_attested_by_operator": True,
            "configuration": {"bytes_per_flow": 1024, "rounds": 6, "parallel": 1, "warmup": 0,
                              "timeout_seconds": 30.0, "fox_transport": "h2-connect",
                              "vless_transport": "reality-vision"},
            "samples": samples,
            "resources": {"fox": {"cpu_percent_one_core": 9.5, "rss_peak_mib": 48},
                          "vless": {"cpu_percent_one_core": 10, "rss_peak_mib": 50}}}


class Stage1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = SOCKSServer(("127.0.0.1", 0), SOCKSHandler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(3)

    def test_end_to_end_private_redacted_report(self):
        socks = f"127.0.0.1:{self.server.server_address[1]}"
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "redacted.json"
            argv = ["--fox-socks", socks, "--vless-socks", socks]
            with self.assertRaises(ValueError):
                runner.validate(runner.parser().parse_args(
                    argv + ["--target", "echo.private.example:9000", "--scenario", "small",
                            "--environment", "lab", "--out", str(out)]))
            secondary = SOCKSServer(("127.0.0.1", 0), SOCKSHandler)
            worker = threading.Thread(target=secondary.serve_forever, daemon=True)
            worker.start()
            try:
                argv = ["--fox-socks", socks,
                        "--vless-socks", f"127.0.0.1:{secondary.server_address[1]}",
                        "--target", "echo.private.example:9000", "--scenario", "small",
                        "--environment", "lab", "--warmup", "0", "--rounds", "3",
                        "--parallel", "2", "--out", str(out)]
                self.assertEqual(runner.main(argv), 0)
                doc = json.loads(out.read_text())
                self.assertEqual(len(doc["samples"]), 12)
                self.assertEqual(doc["schema"], 2)
                self.assertTrue(all(r["completion_ms"] is not None for r in doc["samples"]))
                self.assertEqual(doc["summary"]["fox"]["successful"], 6)
                self.assertFalse(doc["wan_attested_by_operator"])
                self.assertIsNone(doc["resources"])
                self.assertNotIn("echo.private.example", out.read_text())
                self.assertNotIn(socks, out.read_text())
                self.assertEqual(runner.main(argv), 2)  # no overwrite
            finally:
                secondary.shutdown()
                secondary.server_close()
                worker.join(3)

    def test_gate_three_days_valid(self):
        reports = [fake_report(d) for d in (18, 19, 20)]
        result = gate.evaluate(reports)
        self.assertTrue(result["passed"], result["issues"])
        self.assertEqual(result["days_observed"], 3)
        self.assertFalse(result["wan_verified_by_tool"])
        self.assertGreater(result["measurements"][0]["fox_to_vless"]["goodput_ratio"], .9)
        self.assertEqual(result["schema"], 2)
        self.assertEqual(result["measurements"][0]["fox"]["completion_p95_ms"], 15.0)

    def test_gate_fails_without_real_wan_attestation_and_resources(self):
        reports = [fake_report(d) for d in (18, 19, 20)]
        reports[1]["environment"] = "lab"
        reports[2]["resources"] = None
        # Resource monitoring is mandatory for bulk, optional for small exchanges.
        result = gate.evaluate(reports)
        self.assertFalse(result["passed"])
        self.assertIn("WAN topology not operator-attested", result["issues"])
        self.assertNotIn("CPU/RSS comparison missing or unusable", result["issues"])
        reports = [fake_report(d, "bulk") for d in (18, 19, 20)]
        reports[2]["resources"] = None
        result = gate.evaluate(reports)
        self.assertIn("CPU/RSS comparison missing or unusable", result["issues"])

    def test_gate_rejects_slow_and_missing_days(self):
        reports = [fake_report(d, "bulk") for d in (18, 19, 19)]
        for row in reports[0]["samples"]:
            if row["proxy"] == "fox":
                row["payload_mbps"] = 50
        result = gate.evaluate(reports)
        self.assertFalse(result["passed"])
        self.assertIn("FoxTunnel median goodput below 90% VLESS", result["issues"])
        self.assertIn("at least three different UTC measurement days required", result["issues"])

    def test_gate_checks_ids_integrity_and_schema(self):
        reports = [fake_report(d) for d in (18, 19, 20)]
        reports[0]["samples"][1]["round"] = 1
        with self.assertRaisesRegex(ValueError, "duplicate"):
            gate.evaluate(reports)
        reports = [fake_report(d) for d in (18, 19, 20)]
        reports[0]["samples"][0].update(ok=False, integrity_failure=True)
        result = gate.evaluate(reports)
        self.assertFalse(result["passed"])
        self.assertIn("verified echo integrity failure", result["issues"])
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "bad.json"
            path.write_text('{"schema":77}')
            with self.assertRaises(ValueError):
                gate.load(path)

    def test_small_p95_completion_not_one_kilobyte_mbps(self):
        reports = [fake_report(d) for d in (18, 19, 20)]
        for row in reports[0]["samples"]:
            if row["proxy"] == "fox":
                row["payload_mbps"] = 0.01  # low Mbps on tiny packets is irrelevant
        self.assertTrue(gate.evaluate(reports)["passed"])
        for row in reports[0]["samples"]:
            if row["proxy"] == "fox":
                row["transfer_ms"] = 50
                row["completion_ms"] = 60
        result = gate.evaluate(reports)
        self.assertIn("FoxTunnel p95 end-to-end latency above 110% VLESS", result["issues"])

    def test_gate_rejects_inconsistent_timing_or_unidentified_transport(self):
        reports = [fake_report(d) for d in (18, 19, 20)]
        reports[0]["samples"][0]["completion_ms"] = 1
        with self.assertRaisesRegex(ValueError, "invalid measurement"):
            gate.evaluate(reports)
        reports = [fake_report(d) for d in (18, 19, 20)]
        reports[0]["configuration"]["fox_transport"] = None
        with self.assertRaisesRegex(ValueError, "unidentified"):
            gate.evaluate(reports)

    def test_gate_refuses_mixed_workloads(self):
        reports = [fake_report(d) for d in (18, 19, 20)]
        reports[1]["scenario"] = "bulk"
        with self.assertRaisesRegex(ValueError, "mixed scenarios"):
            gate.evaluate(reports)

    def test_process_monitor_linux(self):
        if os.name != "posix" or not Path("/proc/self/stat").exists():
            self.skipTest("Linux proc required")
        ticks, rss, starttime = runner.proc_sample(os.getpid())
        self.assertGreater(starttime, 0)
        self.assertGreaterEqual(ticks, 0)
        self.assertGreater(rss, 0)
        sampler = runner.ResourceSampler({"fox": os.getpid(), "vless": os.getppid()})
        sampler.start()
        resource = sampler.finish()
        self.assertGreaterEqual(resource["fox"]["rss_peak_mib"], 0)
        self.assertGreaterEqual(resource["vless"]["cpu_percent_one_core"], 0)


if __name__ == "__main__":
    unittest.main()
