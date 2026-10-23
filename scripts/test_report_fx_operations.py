import copy
import unittest
from report_fx_operations import measures, MODES


def fixture():
    return {
        "schema": 1, "transport": "h2-connect", "duration_seconds": 300,
        "rounds": 100, "warmup_tunnels": 16, "parallel_streams": 8,
        "payload_bytes_per_round": 131072, "cpu_ticks_per_second": 100,
        "cpu_seconds": 20,
        "samples": [
            {"rss_kib": 1000, "cpu_ticks": 20, "fds": 40, "at_ms": 0},
            {"rss_kib": 2000, "cpu_ticks": 2020, "fds": 50, "at_ms": 300000},
            {"rss_kib": 1500, "cpu_ticks": 2020, "fds": 40, "at_ms": 300100},
        ],
        "counters": {
            "upload_bytes": 116 * 131072, "download_bytes": 116 * 131072,
            "completed": 116, "active": 0, "draining": 0,
            "rejected": 0, "idle_expired": 0, "gc_collections": 2, "gc_ms": 5,
        },
    }


class OperationsReportTests(unittest.TestCase):
    def test_metrics_include_both_transfer_directions(self):
        a = measures(fixture())
        self.assertEqual(a["rss_max_sampled_kib"], 2000)
        self.assertEqual(a["rss_delta_kib"], 500)
        self.assertEqual(a["fd_max_sampled"], 50)
        self.assertGreater(a["cpu_seconds_per_gib"], 0)

    def test_reject_bad_counters(self):
        for key in ("download_bytes", "completed", "rejected"):
            a = fixture()
            a["counters"][key] += 1
            with self.assertRaises(ValueError):
                measures(a)

    def test_reject_corrupt_samples_and_cpu_mismatch(self):
        a = fixture()
        a["samples"][1]["cpu_ticks"] = 9
        with self.assertRaises(ValueError):
            measures(a)
        a = fixture()
        a["cpu_seconds"] = 40
        with self.assertRaises(ValueError):
            measures(a)


if __name__ == "__main__":
    unittest.main()
