import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import build_necko as build


class NeckoSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.original = b"before\nline two\n"
        self.changed = b"after\nline two\n"
        (self.source / "input.cpp").write_bytes(self.original)
        (self.source / "unrelated.cpp").write_text("unrelated\n")
        self.git("init", "-q")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "-qm", "fixture")
        patch = "".join(difflib.unified_diff(
            self.original.decode().splitlines(True), self.changed.decode().splitlines(True),
            fromfile="a/input.cpp", tofile="b/input.cpp"))
        (self.root / "fix.patch").write_text(patch)
        digest = lambda data: hashlib.sha256(data).hexdigest()
        self.lock = {"schema": 1, "revision": self.git("rev-parse", "HEAD"),
                     "platform": "linux-amd64", "patches": [{
                         "path": "fix.patch", "sha256": digest(patch.encode()),
                         "source_path": "input.cpp", "before_sha256": digest(self.original),
                         "after_sha256": digest(self.changed)}]}
        self.lock_path = self.root / "lock.json"
        self.lock_path.write_text(json.dumps(self.lock))

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.source, check=True,
                              text=True, capture_output=True).stdout.strip()

    def test_real_git_patch_and_idempotence(self):
        lock = build.load_lock(self.lock_path, self.root)
        build.prepare(self.source, lock, self.root)
        build.prepare(self.source, lock, self.root)
        self.assertEqual((self.source / "input.cpp").read_bytes(), self.changed)

    def test_changed_output_digest_identifies_the_source_file(self):
        self.lock['patches'][0]['after_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'patched Gecko source digest mismatch: input.cpp'):
            build.prepare(self.source, self.lock, self.root)

    def test_revision_mismatch_does_not_mutate_source(self):
        self.lock["revision"] = "a" * 40
        with self.assertRaisesRegex(ValueError, "revision"):
            build.prepare(self.source, self.lock, self.root)
        self.assertEqual((self.source / "input.cpp").read_bytes(), self.original)

    def test_source_drift_and_unrelated_changes_rejected(self):
        (self.source / "input.cpp").write_text("unexpected\n")
        with self.assertRaisesRegex(ValueError, "source digest"):
            build.prepare(self.source, self.lock, self.root)
        (self.source / "input.cpp").write_bytes(self.original)
        (self.source / "unrelated.cpp").write_text("altered\n")
        with self.assertRaisesRegex(ValueError, "unrelated"):
            build.prepare(self.source, self.lock, self.root)

    def test_tampered_patch_rejected(self):
        (self.root / "fix.patch").write_text("tampered\n")
        with self.assertRaisesRegex(ValueError, "patch digest"):
            build.load_lock(self.lock_path, self.root)

    def test_invalid_second_file_prevents_first_patch(self):
        self.lock["patches"].append({**self.lock["patches"][0], "source_path": "unrelated.cpp"})
        with self.assertRaisesRegex(ValueError, "source digest"):
            build.prepare(self.source, self.lock, self.root)
        self.assertEqual((self.source / "input.cpp").read_bytes(), self.original)

    def test_symlink_outside_source_rejected(self):
        (self.root / "outside.cpp").write_bytes(self.original)
        (self.source / "input.cpp").unlink()
        (self.source / "input.cpp").symlink_to(self.root / "outside.cpp")
        with self.assertRaisesRegex(ValueError, "escapes"):
            build.prepare(self.source, self.lock, self.root)

    def test_mozconfig_cannot_inject_shell_or_enable_artifact_mode(self):
        with self.assertRaisesRegex(ValueError, "metacharacters"):
            build.mozconfig(Path("/tmp/$(touch unsafe)"), 2)
        with self.assertRaisesRegex(ValueError, "jobs"):
            build.mozconfig(Path("/tmp/objects"), 0)
        config = build.mozconfig(Path("/tmp/objects"), 2)
        self.assertIn("--enable-tests", config)
        self.assertNotIn("artifact", config)

    def test_local_build_without_cache_preserves_source_build(self):
        config = build.mozconfig(Path("/tmp/objects"), 4, "none", True)
        self.assertNotIn("--with-ccache", config)
        self.assertIn("--enable-bootstrap=no-update", config)
        self.assertIn("--enable-application=browser", config)
        self.assertNotIn("artifact", config)
        with self.assertRaisesRegex(ValueError, "compiler cache"):
            build.mozconfig(Path("/tmp/objects"), 4, "unsafe")

    def test_repository_lock_and_patch_digests(self):
        build.load_lock()

    def test_vendored_cargo_checksum_tracks_the_patched_source(self):
        lock = build.load_lock()
        patches = {p["source_path"]: p for p in lock["patches"]}
        source = patches["third_party/rust/neqo-http3/src/connection.rs"]
        manifest = patches["third_party/rust/neqo-http3/.cargo-checksum.json"]
        lines = (build.ROOT / manifest["path"]).read_text().splitlines()
        before = json.loads(next(line[1:] for line in lines if line.startswith('-{"files"')))
        after = json.loads(next(line[1:] for line in lines if line.startswith('+{"files"')))
        self.assertEqual(before["files"].pop("src/connection.rs"), source["before_sha256"])
        self.assertEqual(after["files"].pop("src/connection.rs"), source["after_sha256"])
        self.assertEqual(before, after, "all other Cargo integrity entries must be preserved")


if __name__ == "__main__":
    unittest.main()
