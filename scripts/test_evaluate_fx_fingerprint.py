import copy
import unittest

from evaluate_fx_fingerprint import evaluate


def row(field, a, b):
    return {"field": field, "reference": a, "candidate": b,
            "status": "equal" if a == b else "different"}


def reports():
    candidate = {"schema": 1, "kind": "necko-firefox-comparison-report",
                 "runtime_sha256": {"libxul": "abc"}, "source_sha256": {"client": "def"},
                 "observations": []}
    control = {"schema": 1, "kind": "firefox-self-comparison-report",
               "runtime_sha256": {"libxul": "abc"}, "source_sha256": {"client": "def"},
               "observations": []}
    for mode in ("h2-connect", "h3-connect"):
        for i in range(3):
            # Stable settings, and naturally randomized extension order.
            c = [row("connection_1.settings", [1], [1]),
                 row("connection_1.hello.extensions", [10, 16], [10, 16])]
            f = [row("connection_1.settings", [1], [1]),
                 row("connection_1.hello.extensions", [10, 16],
                     [10, 16] if i < 2 else [16, 10])]
            candidate["observations"].append({"transport": mode, "checks": c})
            control["observations"].append({"transport": mode, "checks": f})
    return candidate, control


class FXAuditTests(unittest.TestCase):
    def test_no_difference_does_not_claim_indistinguishability(self):
        c, f = reports()
        result = evaluate(c, f)
        self.assertEqual(result["status"], "no-differences-in-recorded-fields")
        self.assertIn("not ordinary Firefox navigation", result["scope"])
        self.assertEqual(result["unexpected_differences"], 0)

    def test_stable_mismatch_is_reported_and_not_normalized(self):
        c, f = reports()
        for ob in c["observations"][:2]:
            ob["checks"][0] = row("connection_1.settings", [1], [9])
        result = evaluate(c, f)
        self.assertEqual(result["status"], "regression-detected")
        self.assertEqual(result["results"]["h2-connect"]["unexpected_fields"],
                         ["connection_1.settings"])

    def test_sporadic_h2_frame_mismatch_is_visible_but_not_confirmed(self):
        c, f = reports()
        c["observations"][0]["checks"][0] = row("connection_1.settings", [1], [9])
        result = evaluate(c, f)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["unexpected_differences"], 0)
        self.assertEqual(result["sporadic_differences"], 1)
        self.assertEqual(result["results"]["h2-connect"]["sporadic_fields"],
                         ["connection_1.settings"])
        self.assertEqual(result["results"]["h2-connect"]["persistent_mismatch_threshold"], 2)

    def test_self_variation_is_inconclusive_not_a_false_match(self):
        c, f = reports()
        c["observations"][1]["checks"][1] = row("connection_1.hello.extensions", [10, 16], [16, 10])
        result = evaluate(c, f)
        self.assertEqual(result["status"], "inconclusive")
        self.assertEqual(result["results"]["h2-connect"]["inconclusive_fields"],
                         ["connection_1.hello.extensions"])

    def test_persistent_mismatch_is_visible_even_under_variable_control(self):
        c, f = reports()
        for ob in c["observations"]:
            if ob["transport"] == "h3-connect":
                ob["checks"][1] = row("connection_1.hello.extensions",
                                      [10, 16], [16, 10])
        result = evaluate(c, f)
        row_h3 = result["results"]["h3-connect"]
        self.assertEqual(row_h3["persistent_under_variable_control"],
                         ["connection_1.hello.extensions"])
        freq = next(x for x in row_h3["mismatch_frequencies"]
                    if x["field"] == "connection_1.hello.extensions")
        self.assertEqual((freq["candidate"], freq["candidate_total"]), (3, 3))
        self.assertEqual(freq["firefox_self"], 1)
        self.assertEqual(result["status"], "inconclusive")

    def test_rejects_mixed_versions_missing_repetitions_and_schema_drift(self):
        c, f = reports()
        f["source_sha256"]["client"] = "wrong"
        with self.assertRaisesRegex(ValueError, "runtime or source"):
            evaluate(c, f)
        c, f = reports()
        c["observations"] = c["observations"][:2]
        with self.assertRaisesRegex(ValueError, "repetitions"):
            evaluate(c, f)
        c, f = reports()
        c["observations"][0]["checks"].append(row("new_field", True, True))
        with self.assertRaisesRegex(ValueError, "fields differ"):
            evaluate(c, f)

    def test_rejects_inconsistent_status_and_duplicate_fields(self):
        c, f = reports()
        c["observations"][0]["checks"][0]["status"] = "different"
        with self.assertRaisesRegex(ValueError, "inconsistent comparison"):
            evaluate(c, f)
        c, f = reports()
        f["observations"][0]["checks"].append(copy.deepcopy(f["observations"][0]["checks"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluate(c, f)


if __name__ == "__main__":
    unittest.main()
