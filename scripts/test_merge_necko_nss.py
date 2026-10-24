import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import merge_necko_nss as merge


class MergeTests(unittest.TestCase):
    def fixture(self, root):
        necko, nss = root / "necko", root / "nss"
        (necko / "runtime").mkdir(parents=True)
        (necko / "runtime/xpcshell").write_bytes(b"native xpcshell")
        (necko / "foxtunnel-necko").write_bytes(b"helper")
        (necko / "foxtunnel").write_bytes(b"old go only cli")
        (necko / "manifest.json").write_text(json.dumps({
            "schema": 1, "platform": "linux-amd64", "helper_protocol": 1,
            "source_lock_sha256": "a"*64, "client_js_sha256": "b"*64,
            "files": {}
        }))
        (nss / "lib").mkdir(parents=True)
        (nss / "licenses").mkdir(parents=True)
        (nss / "lib/libnss3.so").write_bytes(b"nss native library")
        (nss / "foxtunnel").write_bytes(b"nss cli")
        (nss / "build.json").write_text(json.dumps({
            "build_flavor": "nss", "goarch": "amd64",
            "runtime": {"mozilla": {"libraries": {"libnss3.so": "c"*64}}}
        }))
        (nss / "mozilla-runtime.json").write_text("{}")
        (nss / "licenses/Mozilla-about-license.html").write_text("NSS license")
        (nss / "THIRD_PARTY_NOTICES.txt").write_text("Notices")
        return necko, nss

    def test_merged_manifest_and_deterministic_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            necko, nss = self.fixture(root)
            manifest = merge.merge_files(necko, nss)
            self.assertEqual((necko / "foxtunnel").read_bytes(), b"nss cli")
            for name, digest in manifest["files"].items():
                self.assertEqual(merge.sha(necko / name), digest, name)
            self.assertIn("lib/libnss3.so", manifest["files"])
            self.assertIn("runtime/xpcshell", manifest["files"])
            self.assertIn("nss-build.json", manifest["files"])
            first, second = root / "a.tar.gz", root / "b.tar.gz"
            self.assertEqual(merge.make_archive(necko, first), merge.make_archive(necko, second))
            with tarfile.open(first) as archive:
                self.assertIn("foxtunnel-necko/lib/libnss3.so", archive.getnames())

    def test_refuse_missing_native_files_and_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            necko, nss = self.fixture(root)
            (nss / "mozilla-runtime.json").unlink()
            with self.assertRaises(ValueError):
                merge.merge_files(necko, nss)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            necko, nss = self.fixture(root)
            (necko / "lib").mkdir()
            with self.assertRaises(ValueError):
                merge.merge_files(necko, nss)

    def test_refuse_path_traversal_and_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, kind in (("foxtunnel-necko/../outside", "file"),
                               ("foxtunnel-necko/evil", "symlink")):
                path = root / (kind + ".tar.gz")
                with tarfile.open(path, "w:gz") as tar:
                    info = tarfile.TarInfo(name)
                    if kind == "symlink":
                        info.type = tarfile.SYMTYPE
                        info.linkname = "/etc/passwd"
                        tar.addfile(info)
                    else:
                        data = b"hello"
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                (root / "dest").mkdir(exist_ok=True)
                with self.assertRaises(ValueError):
                    merge.extract_regular(path, root / "dest", prefix="foxtunnel-necko")
                self.assertFalse((root / "outside").exists())


if __name__ == "__main__":
    unittest.main()
