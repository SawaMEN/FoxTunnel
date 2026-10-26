import io
import json
from pathlib import Path
import tarfile
import tempfile
import struct

import package_necko
import unittest

import merge_necko_nss as merge


class MergeTests(unittest.TestCase):
    def fixture(self, root, arch="amd64"):
        necko, nss = root / "necko", root / "nss"
        (necko / "runtime").mkdir(parents=True)
        binary = bytearray(64)
        binary[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI', binary, 16, 3, 62 if arch == 'amd64' else 183, 1)
        for name in ('xpcshell', 'libxul.so', 'libnss3.so'):
            (necko / 'runtime' / name).write_bytes(binary)
        (necko / 'runtime/platform.ini').write_text('pinned runtime')
        (necko / "foxtunnel-necko").write_bytes(binary)
        (necko / "foxtunnel").write_bytes(binary)
        (necko / 'source-lock.json').write_bytes((package_necko.ROOT / 'experiments/firefox-necko/gecko.lock.json').read_bytes())
        lock = json.loads((necko / 'source-lock.json').read_text())
        runtime = {p.name: merge.sha(p) for p in (necko/'runtime').iterdir()}
        (necko / 'provenance.json').write_text(json.dumps(dict(status='built-not-interop-tested', target_platform='linux-'+arch, source=lock, runtime=runtime)))
        self.rehash(necko, arch)
        (nss / "lib").mkdir(parents=True)
        (nss / "licenses").mkdir(parents=True)
        (nss / "lib/libnss3.so").write_bytes(binary)
        (nss / "foxtunnel").write_bytes(binary + b'NSS CLI')
        (nss / "build.json").write_text(json.dumps({
            "build_flavor": "nss", "goarch": arch,
            "runtime": {"mozilla": {"libraries": {"libnss3.so": merge.sha(nss / 'lib/libnss3.so')}}}
        }))
        (nss / "mozilla-runtime.json").write_text("{}")
        (nss / "licenses/Mozilla-about-license.html").write_text("NSS license")
        (nss / "THIRD_PARTY_NOTICES.txt").write_text("Notices")
        return necko, nss

    def rehash(self, necko, arch='amd64'):
        (necko / "manifest.json").write_text(json.dumps({
            "schema": 1, "platform": "linux-"+arch, "helper_protocol": 1,
            "source_lock_sha256": merge.sha(necko/'source-lock.json'),
            "client_js_sha256": merge.sha(package_necko.ROOT/'experiments/firefox-necko/client.js'),
            "files": {p.relative_to(necko).as_posix():merge.sha(p) for p in necko.rglob('*') if p.is_file() and p != necko/'manifest.json'}
        }))

    def test_merged_manifest_and_deterministic_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            necko, nss = self.fixture(root)
            manifest = merge.merge_files(necko, nss)
            self.assertEqual((necko / "foxtunnel").read_bytes(), (nss / "foxtunnel").read_bytes())
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

    def test_both_architectures_reject_rehashed_mixed_binaries_and_tamper(self):
        for arch in ('amd64','arm64'):
            for fault in (None,'mixed','tamper','extra','source'):
                with self.subTest(arch=arch,fault=fault), tempfile.TemporaryDirectory() as tmp:
                    necko,nss=self.fixture(Path(tmp),arch)
                    if fault=='mixed':
                        p=necko/'runtime/libxul.so';data=bytearray(p.read_bytes());struct.pack_into('<H',data,18,183 if arch=='amd64' else 62);p.write_bytes(data);self.rehash(necko,arch)
                    elif fault=='tamper':(necko/'foxtunnel-necko').write_bytes(b'changed')
                    elif fault=='extra':(necko/'extra').write_text('injected')
                    elif fault=='source':
                        p=necko/'provenance.json';d=json.loads(p.read_text());d['source']['revision']='wrong';p.write_text(json.dumps(d));self.rehash(necko,arch)
                    if fault:
                        with self.assertRaises(ValueError):merge.merge_files(necko,nss)
                    else:self.assertEqual(merge.merge_files(necko,nss)['platform'],'linux-'+arch)

    def test_real_producer_archive_roundtrip_including_empty_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);necko,_=self.fixture(root)
            (necko/'runtime/empty').touch();self.rehash(necko)
            path=root/'native.tar.gz';package_necko.archive(necko,path)
            with tarfile.open(path) as tar:self.assertEqual(tar.getnames()[0],'foxtunnel-necko')
            out=root/'out';out.mkdir();merge.extract_regular(path,out,prefix='foxtunnel-necko')
            self.assertTrue((out/'runtime/empty').is_file())
            import necko_bundle
            necko_bundle.verify(out,'linux-amd64')

    def test_only_exact_legacy_root_directory_alias_is_accepted(self):
        for name,kind,good in [('foxtunnel-necko/.','dir',True),('foxtunnel-necko/.','file',False),('foxtunnel-necko/./child','file',False),('foxtunnel-necko/../child','file',False)]:
            with self.subTest(name=name,kind=kind), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);path=root/'a.tar.gz'
                with tarfile.open(path,'w:gz') as tar:
                    m=tarfile.TarInfo(name);m.type=tarfile.DIRTYPE if kind=='dir' else tarfile.REGTYPE;tar.addfile(m)
                    m=tarfile.TarInfo('foxtunnel-necko/empty');tar.addfile(m,io.BytesIO(b''))
                out=root/'out';out.mkdir()
                if good:merge.extract_regular(path,out,prefix='foxtunnel-necko')
                else:
                    with self.assertRaises(ValueError):merge.extract_regular(path,out,prefix='foxtunnel-necko')

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
