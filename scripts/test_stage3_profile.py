"""Offline validation of Stage-3 profiler CLI and report integrity."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import stage3_profile as profile


class Stage3ProfileTests(unittest.TestCase):
    def args(self, out: Path, variant="go-h2", scenario="small", benchtime="200ms"):
        return argparse.Namespace(variant=variant, scenario=scenario,
                                  benchtime=benchtime, out=out)

    def fake_go(self, a, *, fail=False, missing=None):
        expected, _ = profile.VARIANTS[a.variant]
        size, _ = profile.SCENARIOS[a.scenario]
        output = (f"{expected}/{size}-4  100  1250.5 ns/op  "
                  f"50.0 MB/s  1234 B/op  9 allocs/op\n").encode()
        def invoke(cmd, **kwargs):
            self.assertEqual(kwargs["cwd"], profile.ROOT)
            if cmd == ["go", "version"]:
                return subprocess.CompletedProcess(cmd, 0, b"go version go1.26.9 linux/amd64\n", b"")
            self.assertEqual(cmd[:2], ["go", "test"])
            self.assertIn(f"^{expected}$/^{size}$", cmd)
            self.assertIn("-benchmem", cmd)
            self.assertIn("-run", cmd)
            if a.variant == "nss-h2":
                self.assertIn("nss", cmd)
            else:
                self.assertNotIn("-tags", cmd)
            for kind, flag in (("cpu", "-cpuprofile="), ("mem", "-memprofile="),
                               ("block", "-blockprofile="), ("mutex", "-mutexprofile=")):
                option = next(x for x in cmd if x.startswith(flag))
                if kind != missing:
                    Path(option.removeprefix(flag)).write_bytes(b"pprof fixture")
                    if os.name == "posix":
                        Path(option.removeprefix(flag)).chmod(0o600)
            return subprocess.CompletedProcess(cmd, 1 if fail else 0,
                                               b"FAIL\n" if fail else output, b"")
        return invoke

    def test_parse_both_scenarios_and_reject_ambiguity(self):
        for variant in profile.VARIANTS:
            for scenario in profile.SCENARIOS:
                fn, _ = profile.VARIANTS[variant]
                size, bytes_size = profile.SCENARIOS[scenario]
                line = (f"{fn}/{size}-4   7  133.5 ns/op "
                        "  300.1 MB/s  64 B/op  2 allocs/op\n")
                parsed = profile.parse_benchmark(line, variant, scenario)
                self.assertEqual(parsed["iterations"], 7)
                self.assertEqual(parsed["bytes_per_exchange"], bytes_size)
                with self.assertRaises(ValueError):
                    profile.parse_benchmark(line + line, variant, scenario)
                with self.assertRaises(ValueError):
                    profile.parse_benchmark("PASS\n", variant, scenario)
                with self.assertRaises(ValueError):
                    profile.parse_benchmark(line.replace("133.5", "0.0"), variant, scenario)

    def test_reject_overwrite_repository_or_bad_benchtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "profile"
            for value in ("0x", "abc", "1m;echo nope", "100000s", "0ms", "-test"):
                with self.assertRaises(ValueError):
                    profile.validate(self.args(out, benchtime=value))
            with self.assertRaises(ValueError):
                profile.validate(self.args(profile.ROOT / "must-not-write-here"))
            out.mkdir()
            with self.assertRaises(ValueError):
                profile.validate(self.args(out))

    def test_success_private_permissions_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "profiles"
            a = self.args(out, variant="nss-h2", scenario="bulk")
            with patch.object(profile.subprocess, "run", side_effect=self.fake_go(a)):
                report = profile.run(a)
            self.assertEqual(report["variant"], "nss-h2")
            self.assertEqual(report["scenario"], "bulk")
            self.assertEqual(report["benchmark"]["allocations_per_exchange"], 9)
            self.assertEqual(json.loads((out / "summary.json").read_text()), report)
            self.assertFalse(any(str(tmp) in str(item) for item in report.values()))
            for name in ("summary.json", "go-test.log", "cpu.pprof", "mem.pprof",
                         "block.pprof", "mutex.pprof"):
                self.assertGreater((out / name).stat().st_size, 0)
                if os.name == "posix":
                    self.assertEqual((out / name).stat().st_mode & 0o077, 0)
            if os.name == "posix":
                self.assertEqual(out.stat().st_mode & 0o077, 0)
            with self.assertRaises(ValueError):
                profile.run(a)

    def test_failed_go_produces_only_private_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "bad"
            a = self.args(out)
            with patch.object(profile.subprocess, "run", side_effect=self.fake_go(a, fail=True)):
                with self.assertRaisesRegex(RuntimeError, "Go benchmark failed"):
                    profile.run(a)
            self.assertTrue((out / "go-test.log").is_file())
            self.assertFalse((out / "summary.json").exists())

    def test_missing_profile_is_not_a_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "missing"
            a = self.args(out)
            with patch.object(profile.subprocess, "run",
                              side_effect=self.fake_go(a, missing="mutex")):
                with self.assertRaisesRegex(RuntimeError, "complete set"):
                    profile.run(a)
            self.assertFalse((out / "summary.json").exists())


if __name__ == "__main__":
    unittest.main()
