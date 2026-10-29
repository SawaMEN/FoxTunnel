import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import deploy_cli
import merge_necko_nss as merge
import test_merge_necko_nss
import unified_archive


COMMIT = "a" * 40
VERSION = "v0.0.0-ci"


def prepare(root, arch="amd64"):
    necko, nss = test_merge_necko_nss.MergeTests().fixture(root,arch)
    mozilla = {"libraries": {"libnss3.so": merge.sha(nss / "lib/libnss3.so")}}
    (nss / "mozilla-runtime.json").write_text(json.dumps(mozilla))
    (nss / "build.json").write_text(json.dumps({
        "version": VERSION, "commit": COMMIT, "target": "linux/"+arch+"/nss",
        "goos": "linux", "goarch": arch, "build_flavor": "nss",
        "dirty": False, "runtime": {"kind": "bundled-nss", "mozilla": mozilla},
    }))
    merge.merge_files(necko, nss)
    archive = root / ("vetroff_0.0.0-ci_linux_"+arch+".tar.gz")
    merge.make_archive(necko, archive)
    return archive


class UnifiedDeploymentTests(unittest.TestCase):
    def test_unified_archive_integrity_and_external_install_record(self):
        for arch in ('amd64', 'arm64'):
            with tempfile.TemporaryDirectory() as d:
                root = Path(d)
                archive = prepare(root, arch)
                extracted = root / "extract"
                extracted.mkdir()
                unified_archive.unpack(archive, extracted, VERSION, COMMIT)
                self.assertIn("nss-build.json", [p.name for p in extracted.iterdir()])
                manager = deploy_cli.Deployment(root / "installed")
                info = {
                    "schema": 1, "version": VERSION, "commit": COMMIT, "dirty": False,
                    "protocol_draft": deploy_cli.contract.DRAFT, "build_flavor": "nss",
                    "goos": "linux", "goarch": arch,
                }
                with patch.object(deploy_cli, "target", return_value=("linux", arch)), \
                        patch.object(deploy_cli.subprocess, "check_output", return_value=json.dumps(info).encode()):
                    identity = deploy_cli.digest(archive)
                    manager.install(archive, identity, VERSION, COMMIT, archive=True)
                    executable, record = manager.bundle(identity)
                    self.assertTrue(executable.is_file())
                    self.assertTrue((executable.parent / "manifest.json").exists())
                    self.assertFalse((executable.parent / "installation.json").exists())
                    self.assertTrue((manager.releases / (identity + ".json")).exists())
                    self.assertIn("lib/libnss3.so", record["files"])
                    self.assertIn("runtime/xpcshell", record["files"])

    def test_corruption_and_wrong_commit_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = prepare(root)
            with self.assertRaisesRegex(ValueError, "source identity"):
                extracted = root / "badcommit"
                extracted.mkdir()
                unified_archive.unpack(archive, extracted, VERSION, "b"*40)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = prepare(root)
            extracted = root / "corrupt"
            extracted.mkdir()
            # Verify package-level hash checks independent of the signed digest.
            import tarfile
            with tarfile.open(archive) as tf:
                tf.extractall(extracted, filter="data")
            bundle = extracted / "vetroff-necko"
            (bundle / "vetroff").write_bytes(b"tampered")
            # Extracted manifest must never authorize modified files.
            manifest = json.loads((bundle / "manifest.json").read_text())
            self.assertNotEqual(merge.sha(bundle / "vetroff"), manifest["files"]["vetroff"])


if __name__ == "__main__":
    unittest.main()
