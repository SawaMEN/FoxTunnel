"""Stage 6 local resource/soak gate unit tests (no privilege required)."""
import os
import sys
import unittest

import stage6_tun_soak as soak


def row(rss=40960, fds=12, sockets=4):
    return {"rss_kib": rss, "fds": fds, "socket_fds": sockets}


def sample(**changes):
    value = {"launcher": row(), "client": row(), "exit": row()}
    value.update(changes)
    return value


class Stage6ResourceLimits(unittest.TestCase):
    def test_measures_current_native_process(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("Linux /proc only")
        data = soak.resources(os.getpid())
        self.assertGreater(data["rss_kib"], 0)
        self.assertGreater(data["fds"], 0)
        self.assertGreaterEqual(data["socket_fds"], 0)

    def test_stable_processes_pass_and_have_evidence(self):
        report = soak.evaluate([sample(), sample(client=row(40970, 16, 6)), sample()])
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["sample_count"], 3)
        self.assertEqual(report["processes"]["client"]["peak"]["fds"], 16)
        self.assertEqual(report["processes"]["client"]["growth"]["fds"], 0)

    def test_end_growth_and_peak_are_real_failure_gates(self):
        broken = [
            ("fd growth", row(fds=12 + soak.MAX_FD_GROWTH + 1)),
            ("socket growth", row(sockets=4 + soak.MAX_SOCKET_GROWTH + 1)),
            ("rss growth", row(rss=40960 + soak.MAX_RSS_GROWTH_KIB + 1)),
            ("rss peak", row(rss=soak.MAX_RSS_KIB + 1)),
            ("fd peak", row(fds=soak.MAX_FDS + 1)),
        ]
        for name, value in broken:
            with self.subTest(name=name):
                report = soak.evaluate([sample(), sample(), sample(client=value)])
                self.assertFalse(report["passed"])
                self.assertFalse(report["processes"]["client"]["passed"])

    def test_peak_breach_fails_even_if_final_recovers(self):
        report = soak.evaluate([
            sample(), sample(exit=row(rss=soak.MAX_RSS_KIB + 1)), sample(),
        ])
        self.assertFalse(report["passed"])

    def test_incomplete_or_inconsistent_samples_fail_closed(self):
        with self.assertRaises(ValueError):
            soak.evaluate([sample(), sample()])
        with self.assertRaises(ValueError):
            soak.evaluate([sample(), sample(), {"launcher": row()}])
        with self.assertRaises(ValueError):
            soak.evaluate([sample(), sample(), sample(client={"fds": -1})])


class Stage6SoakRunner(unittest.TestCase):
    def run_fake(self, *, ok=True):
        clock = [0.0]
        def now():
            return clock[0]
        def sleep(n):
            clock[0] += n
        probes = []
        def probe(ns, kind, host, port):
            self.assertEqual(ns, "isolated-netns")
            probes.append((kind, host, port))
            return ok
        return soak.run(
            "isolated-netns", {"launcher": 100, "client": 101, "exit": 102},
            1.0, probe=probe, sample=lambda pid: row(),
            sleep=sleep, clock=now,
        ), probes

    def test_bounded_parallel_all_families(self):
        report, probes = self.run_fake()
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["batches"], 4)
        self.assertEqual(report["max_parallel"], soak.MAX_WORKERS)
        self.assertEqual(len(probes), 4 * len(soak.PROBES))
        self.assertEqual(sum(x["succeeded"] for x in report["load"].values()), len(probes))

    def test_a_single_failed_application_probe_fails_soak(self):
        report, _ = self.run_fake(ok=False)
        self.assertFalse(report["passed"])
        self.assertTrue(report["resources"]["passed"])

    def test_refuses_invalid_duration_or_process_aliases(self):
        with self.assertRaises(ValueError):
            soak.run("netns", {"launcher": 1, "client": 1, "exit": 2}, 1, probe=lambda *_: True)
        with self.assertRaises(ValueError):
            soak.run("netns", {"launcher": 1, "client": 2, "exit": 3}, 121, probe=lambda *_: True)


if __name__ == "__main__":
    unittest.main()
