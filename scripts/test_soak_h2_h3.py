"""Private-safe offline checks of stage-9 memory and result classification."""
import unittest

import soak_h2_h3 as soak


class Stage9Contracts(unittest.TestCase):
    def test_positive_time_bounds(self):
        self.assertEqual(soak.positive("75"), 75)
        for invalid in ("0", "-1", "601"):
            with self.assertRaises(Exception):
                soak.positive(invalid)

    def test_ci_argument_contract(self):
        args = soak.parser().parse_args([
            "--binary", "foxtunnel", "--cert", "cert.pem",
            "--key", "key.pem", "--out", "results.json",
            "--seconds", "75", "--parallel", "3",
            "--minimum-success", "98",
        ])
        self.assertEqual(args.minimum_success, 98)
        self.assertEqual(args.parallel, 3)

    def test_summarize_healthy_samples(self):
        good = {"ok": True, "connect_ms": 12.0, "payload_mbps": 3.2}
        stats = soak.bench.summarize([good, good])
        self.assertEqual(stats["successful"], 2)
        self.assertEqual(stats["success_percent"], 100)

    def test_memory_report_growth_and_peak(self):
        class Proc:
            pid = 100000
        m = soak.Memory({"NSS-H2": Proc()})
        m.first = {"NSS-H2": {"rss_kib": 100, "fd_count": 5, "threads": 4}}
        m.last = {"NSS-H2": {"rss_kib": 115, "fd_count": 4, "threads": 3}}
        m.peak = {"NSS-H2": {"rss_kib": 130, "fd_count": 9, "threads": 5}}
        report = m.report()["NSS-H2"]
        self.assertEqual(report["rss_growth_kib"], 15)
        self.assertEqual(report["peak_fd_count"], 9)
        self.assertEqual(report["peak_rss_kib"], 130)


if __name__ == "__main__":
    unittest.main()
