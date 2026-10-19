"""Stage 10 strict evidence boundaries: no fabricated Naive or QUIC parity."""
import argparse
import json
from pathlib import Path
import tempfile
import unittest
import fingerprint_audit as audit


class FingerprintAuditContract(unittest.TestCase):
    def test_historical_fox_differs(self):
        root = Path(__file__).resolve().parents[1]
        a, _ = audit.read_profile(root / "docs/measurements/2026-10-18/firefox-158-linux.json", "tls_h2")
        b, _ = audit.read_profile(root / "docs/measurements/2026-10-19/nss-firefox158-page.json", "tls_h2")
        c = audit.compare(a, b, None, None)
        self.assertGreater(c["tls"]["counts"]["different"], 0)
        self.assertEqual(c["http2"]["checks"][0]["status"], "different")
        self.assertFalse(c["metadata_equal"])
        self.assertEqual(c["quic_http3"]["counts"]["not_measured"], len(audit.H3_FIELDS))

    def test_settings_order_matters(self):
        a = {"initial_h2_settings": [{"id": 1, "value": 20}, {"id": 2, "value": 0}]}
        b = {"initial_h2_settings": list(reversed(a["initial_h2_settings"]))}
        c = audit.compare(a, b, None, None)["http2"]["checks"]
        self.assertEqual(c[0]["status"], "different")
        self.assertEqual(c[2]["status"], "equal")

    def test_unmeasured_is_not_equal(self):
        self.assertEqual(audit.field_row("hello.alpn", {}, {})["status"], "not_observed")
        self.assertEqual(audit.field_row("hello.alpn", {}, None)["status"], "not_measured")
        c = audit.compare(None, None, None, None)
        self.assertFalse(c["metadata_equal"])
        self.assertEqual(c["tls"]["counts"]["equal"], 0)

    def test_report_honestly_marks_missing_naive_and_quic(self):
        root = Path(__file__).resolve().parents[1]
        args = argparse.Namespace(
            firefox=root / "docs/measurements/2026-10-18/firefox-158-linux.json",
            foxtunnel=root / "docs/measurements/2026-10-19/nss-firefox158-page.json",
            naive=None, firefox_quic=None, foxtunnel_quic=None, naive_quic=None)
        result = audit.report(args)
        self.assertFalse(result["subjects"]["naive"]["tls_h2_observed"])
        self.assertFalse(result["all_three_and_both_protocols_measured"])
        self.assertEqual(result["comparisons_to_firefox"]["naive"]["tls"]["counts"]["not_measured"],
                         len(audit.TLS_FIELDS))
        self.assertNotIn("https://", json.dumps(result))

    def test_quic_requires_decoded_observation(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "h3.json"
            p.write_text('{"schema":1,"quic":{},"h3":{}}')
            with self.assertRaises(ValueError):
                audit.read_profile(p, "h3_quic")
            p.write_text('{"schema":1,"kind":"h3-quic-observation",'
                         '"quic":{"version":1,"tls_alpn":"h3"},'
                         '"h3":{"settings":[{"id":1,"value":3}]}}')
            o, digest = audit.read_profile(p, "h3_quic")
            self.assertEqual(o["quic"]["version"], 1)
            self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
