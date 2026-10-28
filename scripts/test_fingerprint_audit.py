"""Stage 10 strict evidence boundaries: no fabricated Naive or QUIC parity."""
import argparse
import copy
import hashlib
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
            vetroffproxy=root / "docs/measurements/2026-10-19/nss-firefox158-page.json",
            naive=None, firefox_quic=None, vetroffproxy_quic=None, naive_quic=None)
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
            with self.assertRaises(ValueError):
                audit.read_profile(p, "h3_quic")
            p.write_text('{"schema":1,"kind":"h3-quic-observation",'
                         '"capture_method":"endpoint","capture_scenario":"controlled local H3 GET",'
                         '"quic":{"version":1,"tls_alpn":"h3","initial_datagram_size":1200,'
                         '"transport_parameters":[{"id":1,"value":2000}]},'
                         '"h3":{"settings":[{"id":1,"value":3}]}}')
            o, digest = audit.read_profile(p, "h3_quic")
            self.assertEqual(o["quic"]["version"], 1)
            self.assertEqual(len(digest), 64)


    def test_rejects_tampered_tls_vectors_and_digest(self):
        root = Path(__file__).resolve().parents[1]
        source = root / "docs/measurements/2026-10-18/firefox-158-linux.json"
        original = json.loads(source.read_text())
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered.json"
            for field, modified in (
                    ("cipher_suites", [4865, 4866]),
                    ("ja3", "not-a-real-ja3"),
                    ("ja3_md5", "0" * 32)):
                capture = copy.deepcopy(original)
                capture["hello"][field] = modified
                path.write_text(json.dumps(capture))
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "JA3"):
                    audit.read_profile(path, "tls_h2")

    def test_tampered_ja3_hash_even_when_vectors_unchanged(self):
        root = Path(__file__).resolve().parents[1]
        original = json.loads((root / "docs/measurements/2026-10-18/firefox-158-linux.json").read_text())
        valid = audit.ja3_expected(original["hello"])
        self.assertEqual(valid, original["hello"]["ja3"])
        self.assertEqual(hashlib.md5(valid.encode("ascii")).hexdigest(), original["hello"]["ja3_md5"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            original["hello"]["ja3_md5"] = "bad"
            path.write_text(json.dumps(original))
            with self.assertRaisesRegex(ValueError, "JA3"):
                audit.read_profile(path, "tls_h2")

    def test_h3_rejects_duplicate_and_invalid_decoded_identifiers(self):
        template = {
            "schema": 1, "kind": "h3-quic-observation",
            "capture_method": "endpoint", "capture_scenario": "local H3 GET",
            "quic": {"version": 1, "tls_alpn": "h3", "initial_datagram_size": 1200,
                     "transport_parameters": [{"id": 1, "value": 50}]},
            "h3": {"settings": [{"id": 6, "value": 3}]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "quic.json"
            path.write_text(json.dumps(template))
            audit.read_profile(path, "h3_quic")
            for mutated in (
                    {"quic": {"transport_parameters": [{"id": 1, "value": 50},
                                                        {"id": 1, "value": 80}]}},
                    {"h3": {"settings": [{"id": "x", "value": 3}]}},
                    {"h3": {"settings": [{"id": 6, "value": 3},
                                        {"id": 6, "value": 8}]}}):
                capture = copy.deepcopy(template)
                for key, values in mutated.items():
                    capture[key].update(values)
                path.write_text(json.dumps(capture))
                with self.assertRaisesRegex(ValueError, "decoded QUIC/H3"):
                    audit.read_profile(path, "h3_quic")
            with self.assertRaisesRegex(ValueError, "unsupported observation"):
                audit.read_profile(path, "wrong_kind")


if __name__ == "__main__":
    unittest.main()
