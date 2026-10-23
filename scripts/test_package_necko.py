import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import package_necko as bundle


class PackageTests(unittest.TestCase):
    def fixture(self, root):
        runtime = root / 'runtime'
        runtime.mkdir()
        hashes = {}
        for name in ('xpcshell', 'libxul.so', 'libnss3.so', 'platform.ini'):
            (runtime / name).write_bytes(name.encode())
            hashes[name] = bundle.digest(runtime / name)
        provenance = root / 'provenance.json'
        provenance.write_text(json.dumps(dict(status='built-not-interop-tested',
            source=json.loads((bundle.ROOT / 'experiments/firefox-necko/gecko.lock.json').read_text()), runtime=hashes)))
        launcher = root / 'launcher'
        launcher.write_bytes(b'fixture launcher')
        return runtime, provenance, launcher

    def test_package_digests_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.fixture(root)
            out = root / 'bundle'
            manifest = bundle.package(*args, out)
            for name, digest in manifest['files'].items():
                self.assertEqual(bundle.digest(out / name), digest)
            with self.assertRaises(ValueError):
                bundle.package(*args, out)
            bundle.archive(out, root / 'a.tar.gz')
            bundle.archive(out, root / 'b.tar.gz')
            self.assertEqual(bundle.digest(root / 'a.tar.gz'), bundle.digest(root / 'b.tar.gz'))

    def test_recursive_output_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime, provenance, launcher = self.fixture(root)
            with self.assertRaises(ValueError):
                bundle.package(runtime, provenance, launcher, runtime / 'nested')
            self.assertFalse((runtime / 'nested').exists())
            out = root / 'bundle'
            bundle.package(runtime, provenance, launcher, out)
            with self.assertRaises(ValueError):
                bundle.archive(out, out / 'recursive.tar.gz')

    def test_source_mismatch_tamper_and_links(self):
        for fault in ('source', 'tamper', 'symlink'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                runtime, provenance, launcher = self.fixture(root)
                if fault == 'source':
                    data = json.loads(provenance.read_text())
                    data['source']['revision'] = 'wrong'
                    provenance.write_text(json.dumps(data))
                elif fault == 'tamper':
                    (runtime / 'libxul.so').write_bytes(b'altered')
                else:
                    (runtime / 'injected').symlink_to('/etc/passwd')
                with self.assertRaises(ValueError):
                    bundle.package(runtime, provenance, launcher, root / 'bundle')
                self.assertFalse((root / 'bundle').exists())


if __name__ == '__main__':
    unittest.main()
