"""Offline tamper checks for the standalone Mozilla release verifier."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import mozilla_release_verify as release

TAG = "v0.1.0-alpha.2"
COMMIT = "a" * 40


class MozillaReleaseVerifyContracts(unittest.TestCase):
    def make(self, path, *, tamper=False, member_name="LICENSE"):
        filename = f"foxtunnel_{TAG[1:]}_linux_amd64_mozilla.tar.gz"
        archive = path / filename
        data = b"test-data"
        with tarfile.open(archive, "w:gz") as tar:
            member = tarfile.TarInfo(member_name)
            member.size = len(data)
            member.mode = 0o644
            tar.addfile(member, io.BytesIO(data))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        if tamper:
            checksum = "0" * 64
        metadata = path / (filename + ".metadata.json")
        metadata.write_text(json.dumps({
            "schema": 1, "version": TAG, "commit": COMMIT,
            "target": "linux/amd64/mozilla", "artifact": filename,
            "tests_run": False, "published": False,
            "size": archive.stat().st_size, "sha256": checksum
        }))
        return archive, metadata

    def test_rejects_external_checksum_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, m = self.make(Path(tmp), tamper=True)
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                release.validate_bundle(a, m, TAG, COMMIT)

    def test_rejects_traversal_before_extracting(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, m = self.make(Path(tmp), member_name="../leak.txt")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                release.validate_bundle(a, m, TAG, COMMIT)

    def test_rejects_missing_required_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, m = self.make(Path(tmp))
            with self.assertRaisesRegex(ValueError, "missing essential"):
                release.validate_bundle(a, m, TAG, COMMIT)

    def test_rejects_untrusted_expected_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, m = self.make(Path(tmp))
            with self.assertRaisesRegex(ValueError, "trusted full"):
                release.validate_bundle(a, m, TAG, "unknown")

    def test_release_metadata_must_not_claim_tests_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, m = self.make(Path(tmp))
            data = json.loads(m.read_text())
            data["tests_run"] = True
            m.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "tests_run"):
                release.validate_bundle(a, m, TAG, COMMIT)


if __name__ == "__main__":
    unittest.main()
