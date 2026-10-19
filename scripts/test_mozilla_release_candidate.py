"""Review-gate contracts: prerelease cannot publish on ordinary code pushes."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import mozilla_release_candidate as gate


class RequestGate(unittest.TestCase):
    def make(self, location, version="v0.1.0-alpha.2", data=None):
        root = Path(location)
        (root / ".github").mkdir()
        (root / "docs/releases").mkdir(parents=True)
        (root / ".github/mozilla-release-candidate.json").write_text(json.dumps(
            data if data is not None else {"schema": 1, "version": version}
        ))
        (root / f"docs/releases/{version}.md").write_text("Experimental release\n")
        return root

    def test_refuses_non_update_and_non_push(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.make(d)
            for event, ref in [("push", "refs/heads/main"),
                               ("pull_request", "refs/heads/update"),
                               ("workflow_dispatch", "refs/heads/update")]:
                with self.assertRaises(ValueError):
                    gate.resolve(root, event, ref)

    def test_refuses_new_fields_and_unstable_non_alpha_version(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.make(d, data={"schema": 1, "version": "v0.1.0-alpha.2", "publish": True})
            with self.assertRaisesRegex(ValueError, "fields"):
                gate.resolve(root, "push", "refs/heads/update")
        with tempfile.TemporaryDirectory() as d:
            root = self.make(d, version="v1.0.0")
            with self.assertRaisesRegex(ValueError, "experimental"):
                gate.resolve(root, "push", "refs/heads/update")

    def test_refuses_unchanged_request(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.make(d)
            with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
                with self.assertRaisesRegex(ValueError, "triggering commit"):
                    gate.resolve(root, "push", "refs/heads/update")

    def test_valid_new_request(self):
        with tempfile.TemporaryDirectory() as d:
            root = self.make(d)
            with patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                self.assertEqual(gate.resolve(root, "push", "refs/heads/update"),
                                 "v0.1.0-alpha.2")


if __name__ == "__main__":
    unittest.main()
