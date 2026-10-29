import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import package_necko as bundle


class PackageTests(unittest.TestCase):
    def fixture(self, root, target='linux-amd64'):
        binary = bytearray(64)
        binary[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI', binary, 16, 3, 183 if target == 'linux-arm64' else 62, 1)
        runtime = root / 'runtime'
        runtime.mkdir()
        hashes = {}
        for name in ('xpcshell', 'libxul.so', 'libnss3.so', 'platform.ini'):
            (runtime / name).write_bytes(name.encode() if name == 'platform.ini' else binary)
            hashes[name] = bundle.digest(runtime / name)
        provenance = root / 'provenance.json'
        provenance.write_text(json.dumps(dict(status='built-not-interop-tested',
            target_platform=target, source=json.loads((bundle.ROOT / 'experiments/firefox-necko/gecko.lock.json').read_text()), runtime=hashes)))
        launcher = root / 'launcher'
        launcher.write_bytes(binary)
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

    def test_arm64_bundle_and_mixed_architecture_rejection(self):
        for fault in (None, 'xpcshell', 'libxul.so', 'libnss3.so', 'launcher', 'cli', 'label'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                runtime, provenance, launcher = self.fixture(root, 'linux-arm64')
                cli = root / 'cli'
                cli.write_bytes(launcher.read_bytes())
                if fault == 'label':
                    record = json.loads(provenance.read_text())
                    record['target_platform'] = 'linux-amd64'
                    provenance.write_text(json.dumps(record))
                elif fault:
                    path = launcher if fault == 'launcher' else cli if fault == 'cli' else runtime / fault
                    binary = bytearray(path.read_bytes())
                    struct.pack_into('<H', binary, 18, 62)
                    path.write_bytes(binary)
                    # Rehashing the mismatched runtime must not make it acceptable.
                    if fault in ('xpcshell', 'libxul.so', 'libnss3.so'):
                        record = json.loads(provenance.read_text())
                        record['runtime'][fault] = bundle.digest(path)
                        provenance.write_text(json.dumps(record))
                if fault:
                    with self.assertRaisesRegex(ValueError, 'ELF architecture'):
                        bundle.package(runtime, provenance, launcher, root / 'bundle', cli)
                    self.assertFalse((root / 'bundle').exists())
                else:
                    manifest = bundle.package(runtime, provenance, launcher, root / 'bundle', cli)
                    self.assertEqual(manifest['platform'], 'linux-arm64')

    def test_main_cli_is_packaged_as_vetroff_on_both_architectures(self):
        for target in ('linux-amd64', 'linux-arm64'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                runtime, provenance, launcher = self.fixture(root, target)
                cli = root / 'main-cli'
                cli.write_bytes(launcher.read_bytes())
                out = root / 'bundle'
                manifest = bundle.package(runtime, provenance, launcher, out, cli)
                self.assertIn('vetroff', manifest['files'])
                self.assertEqual(bundle.digest(out / 'vetroff'), manifest['files']['vetroff'])
                self.assertTrue((out / 'vetroff').stat().st_mode & 0o111)

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
