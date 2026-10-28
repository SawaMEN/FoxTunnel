"""Offline validation for stage-8 field orchestration. No public servers used."""
import argparse
import json
import tempfile
import unittest
from pathlib import Path

import field_h2_h3 as f


class FieldH2H3Validation(unittest.TestCase):
    def test_rejects_credentials_in_url(self):
        for url in ("http://example.org", "https://u:p@example.org",
                    "https://example.org/secret", "https://example.org?key=secret"):
            with self.assertRaises(argparse.ArgumentTypeError):
                f.server_url(url)
        self.assertEqual(f.server_url("https://example.org:443/"), "https://example.org:443")

    def test_cli_supports_verified_name_for_numeric_ip(self):
        args = f.build_parser().parse_args([
            "--binary", "vetroff", "--server", "https://127.0.0.1:8443",
            "--sni", "localhost", "--target", "127.0.0.1:9000",
            "--out", "private.json",
        ])
        self.assertEqual(args.sni, "localhost")

    def test_fallback_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            f.expected_routes("none", "h2")
        f.expected_routes("h2", "h2")
        f.expected_routes("none", "h3")

    def test_status_parse_skips_other_log_lines(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "status.log"
            path.write_text(
                'starting\nengine_status={"schema":1,"h3_selected":3}\n'
                'engine_status=bad JSON\n'
            )
            self.assertEqual(f.latest_status(path)["h3_selected"], 3)

    def test_samples_redact_raw_errors(self):
        rows = [{
            "proxy": "NSS-H2", "round": 1, "flow": 1, "ok": False,
            "connect_ms": None, "transfer_ms": None, "payload_mbps": None,
            "error": "ConnectionError: remote private.example:10443",
        }]
        s = f.sanitized_samples(rows)[0]
        self.assertEqual(s["error_category"], "ConnectionError")
        self.assertNotIn("private.example", json.dumps(s))

    def test_route_evidence_counts_only_matching_route(self):
        snap = {"h3_selected": 9, "h2_selected": 0}
        self.assertTrue(f.route_evidence(snap, "h3", 1)["observed"])
        self.assertFalse(f.route_evidence(snap, "h2", 1)["observed"])

    def test_non_privileged_loopback_ports(self):
        self.assertEqual(f.listen_port("11080"), 11080)
        with self.assertRaises(argparse.ArgumentTypeError):
            f.listen_port("443")


if __name__ == "__main__":
    unittest.main()
