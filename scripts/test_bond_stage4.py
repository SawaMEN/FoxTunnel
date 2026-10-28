"""Stage-4 lab-only probe/report tests, no public network calls."""
from __future__ import annotations

import argparse
import datetime as dt
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stderr

import bond_stage4_field as field
import bond_stage4_gate as gate
import compare_transports as tcp


class LocalUDPSOCKS:
    """Tiny test-only mock: real sockets, not a real VetroffProxy HTTPS server."""
    def __enter__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(.25)
        self.control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.control.bind(("127.0.0.1", 0))
        self.control.listen(1)
        self.control.settimeout(.25)
        self.closed = threading.Event()

        def serve():
            connection = None
            while not self.closed.is_set():
                try:
                    connection, _ = self.control.accept()
                    break
                except socket.timeout:
                    continue
            if connection is None:
                return
            with connection:
                connection.settimeout(2)
                assert tcp.exact(connection, 3) == b"\x05\x01\x00"
                connection.sendall(b"\x05\x00")
                assert tcp.exact(connection, 10) == b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
                connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
                                   self.udp.getsockname()[1].to_bytes(2, "big"))
                while not self.closed.is_set():
                    try:
                        self.udp.settimeout(.2)
                        frame, source = self.udp.recvfrom(1233)
                    except socket.timeout:
                        continue
                    self.udp.sendto(frame, source)

        self.worker = threading.Thread(target=serve, daemon=True)
        self.worker.start()
        return tcp.Address("127.0.0.1", self.control.getsockname()[1])

    def __exit__(self, *_):
        self.closed.set()
        self.control.close()
        self.udp.close()
        self.worker.join(timeout=3)


def document(mode="tcp", day=1, label="legacy", value=10.0, rate=100.0,
             count=6, ok=True, scenario="small"):
    rows = []
    for i in range(count):
        row = {"proxy": label, "ok": ok, "round": i + 1, "flow": 1, "error_category": None}
        if mode == "tcp":
            row.update(completion_ms=value if ok else None, payload_mbps=rate if ok else None)
        else:
            row.update(rtt_ms=value if ok else None)
        rows.append(row)
    return {"schema": 1, "kind": "vetroff-stage4-field", "mode": mode,
            "created_at_utc": f"2026-10-0{day}T10:00:00+00:00",
            "environment": "wan", "external_topology": "user-attested-unverified",
            "scenario": scenario,
            "configuration": {"bytes_per_flow": 1024 if scenario == "small" else 33554432,
                              "distinct_target_count": 2 if mode == "udp" else 1},
            "samples": rows}


class Stage4Tests(unittest.TestCase):
    def test_udp_wire_ipv4_domain_ipv6_and_reject_bad(self):
        for target in ("127.0.0.1", "echo.example", "::1"):
            frame = field.udp_packet(tcp.Address(target, 12345), b"payload")
            self.assertEqual(field.udp_payload(frame), b"payload")
        for bad in (b"", b"\x01" * 10, b"\x00\x00\x01" + b"\x00" * 10,
                    b"\x00\x00\x00\x03\xff"):
            with self.assertRaises(ValueError):
                field.udp_payload(bad)
        with self.assertRaises(ValueError):
            field.udp_packet(tcp.Address("127.0.0.1", 1234), b"x" * 1220)

    def test_real_socket_udp_echo_trial(self):
        with LocalUDPSOCKS() as proxy:
            rows = field.udp_flow(proxy, tcp.Address("127.0.0.1", 9001),
                                  rounds=5, timeout=2, warmup=2)
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(r["ok"] and r["rtt_ms"] >= 0 for r in rows))

    def test_jitter_ignores_different_exit_flows(self):
        rows = [
            {"ok": True, "flow": 1, "round": 1, "rtt_ms": 5.0},
            {"ok": True, "flow": 2, "round": 1, "rtt_ms": 90.0},
            {"ok": True, "flow": 1, "round": 2, "rtt_ms": 5.5},
            {"ok": True, "flow": 2, "round": 2, "rtt_ms": 90.5},
        ]
        self.assertEqual(field.per_flow_jitter(rows), 0.5)
        self.assertEqual(gate.metrics_of(rows, "udp")["jitter_mean_abs_delta_ms"], 0.5)

    def test_preflight_rejects_unattested_wan_and_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "report.json"
            args = field.parser().parse_args(["--mode", "tcp", "--proxy", "legacy=127.0.0.1:11080",
                "--target", "127.0.0.1:9000", "--scenario", "small",
                "--environment", "wan", "--out", str(out)])
            with self.assertRaisesRegex(ValueError, "independent-VDS"):
                field.validate(args)
            args.confirm_independent_vds = True
            self.assertEqual(len(field.validate(args)[0]), 1)
            out.write_text("{}")
            with self.assertRaisesRegex(ValueError, "already exists"):
                field.validate(args)

    def test_report_hides_destinations_and_raw_error(self):
        rows = [{"ok": False, "error_category": "TimeoutError", "rtt_ms": None},
                {"ok": True, "rtt_ms": 6.3, "error_category": None}]
        out = field.summarize(rows, "udp")
        self.assertEqual(out["loss_pct"], 50)
        self.assertEqual(out["rtt_p95_ms"], 6.3)

    def test_gate_pass_three_days_equal_scenarios(self):
        baseline = [document(day=d, label="legacy", value=10.0) for d in (1, 2, 3)]
        candidate = [document(day=d, label="adaptive", value=10.5) for d in (1, 2, 3)]
        verdict = gate.gate_report_set(baseline, candidate, "legacy", "adaptive")
        self.assertTrue(verdict["passed"], verdict["issues"])
        self.assertTrue(verdict["ready_for_release_gate"])
        self.assertFalse(verdict["wan_verified_by_tool"])

    def test_gate_rejects_regressions_and_missing_days(self):
        base = [document(day=d, label="legacy", value=10, rate=100) for d in (1, 2, 3)]
        slow = [document(day=d, label="adaptive", value=14, rate=100) for d in (1, 2, 3)]
        bad = gate.gate_report_set(base, slow, "legacy", "adaptive")
        self.assertFalse(bad["passed"])
        self.assertIn("p95 completion latency regressed >10%", bad["issues"])
        missing = gate.gate_report_set(base[:1], slow[:1], "legacy", "adaptive")
        self.assertFalse(missing["passed"])
        self.assertTrue(any("3 separate" in s for s in missing["issues"]))

    def test_gate_bulk_speed_and_udp_loss(self):
        base = [document(day=d, label="legacy", value=10, rate=100, scenario="bulk") for d in (1, 2, 3)]
        slow = [document(day=d, label="adaptive", value=10, rate=80, scenario="bulk") for d in (1, 2, 3)]
        self.assertIn("median TCP goodput regressed >10%",
                      gate.gate_report_set(base, slow, "legacy", "adaptive")["issues"])
        udp_base = [document("udp", d, "legacy", value=10) for d in (1, 2, 3)]
        udp_bad = [document("udp", d, "adaptive", value=14) for d in (1, 2, 3)]
        self.assertIn("UDP p95 RTT regressed >10%",
                      gate.gate_report_set(udp_base, udp_bad, "legacy", "adaptive")["issues"])

    def test_gate_rejects_integrity_error_and_mixed_environment(self):
        base = [document(day=d, label="legacy") for d in (1, 2, 3)]
        alt = [document(day=d, label="adaptive") for d in (1, 2, 3)]
        alt[0]["samples"][0].update(ok=False, completion_ms=None,
                                     payload_mbps=None, error_category="ValueError")
        self.assertIn("possible payload integrity failure",
                      " ".join(gate.gate_report_set(base, alt, "legacy", "adaptive")["issues"]))
        alt[0]["environment"] = "lab"
        with self.assertRaisesRegex(ValueError, "mix lab and WAN"):
            gate.gate_report_set(base, alt, "legacy", "adaptive")

    def test_wan_gate_refuses_lab_even_if_lab_passes(self):
        baseline = [document(day=d, label="legacy") for d in (1, 2, 3)]
        adaptive = [document(day=d, label="adaptive") for d in (1, 2, 3)]
        for r in baseline + adaptive:
            r["environment"] = "lab"
            r["external_topology"] = "lab"
        with self.assertRaisesRegex(ValueError, "needs user-attested WAN"):
            gate.gate_report_set(baseline, adaptive, "legacy", "adaptive")
        checked = gate.gate_report_set(baseline, adaptive, "legacy", "adaptive", require_wan=False)
        self.assertTrue(checked["passed"])
        self.assertFalse(checked["ready_for_release_gate"])

    def test_schema_rejects_unknown_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text('{"schema": 99}')
            with self.assertRaisesRegex(ValueError, "unknown stage-4"):
                gate.load_report(path)


if __name__ == "__main__":
    unittest.main()
