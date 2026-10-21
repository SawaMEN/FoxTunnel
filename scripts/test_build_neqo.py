import io
import copy
import json
from pathlib import Path
import tempfile
import unittest
import tomllib
import hashlib
import subprocess
from unittest import mock

import build_neqo


class NeqoBuildIntegrity(unittest.TestCase):
    def test_source_patch_is_pinned_repeatable_and_rejects_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'checkout'
            target = source / 'neqo-http3/src/connection.rs'
            target.parent.mkdir(parents=True)
            target.write_text('old\n')
            subprocess.run(['git', 'init', '-q', source], check=True)
            subprocess.run(['git', '-C', source, 'add', '.'], check=True)
            subprocess.run(['git', '-C', source, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            revision = subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip()
            patch_file = root / 'fix.patch'
            patch_file.write_text('--- a/neqo-http3/src/connection.rs\n+++ b/neqo-http3/src/connection.rs\n@@ -1 +1 @@\n-old\n+new\n')
            digest = lambda b: hashlib.sha256(b).hexdigest()
            patch = dict(path='fix.patch', sha256=digest(patch_file.read_bytes()), source_path='neqo-http3/src/connection.rs', before_sha256=digest(b'old\n'), after_sha256=digest(b'new\n'))
            with mock.patch.object(build_neqo, 'ROOT', root):
                build_neqo.apply_source_patch(source, patch, revision)
                build_neqo.apply_source_patch(source, patch, revision)
                self.assertEqual(target.read_bytes(), b'new\n')
                with self.assertRaisesRegex(ValueError, 'revision'):
                    build_neqo.apply_source_patch(source, patch, '0' * 40)
                target.write_text('unreviewed\n')
                with self.assertRaises(ValueError):
                    build_neqo.apply_source_patch(source, patch, revision)

    def test_transitive_protocol_and_compiler_pin_drift(self):
        lock = json.loads(build_neqo.LOCK.read_text())
        cargo = tomllib.loads((build_neqo.CRATE / 'Cargo.lock').read_text())
        for name in ('neqo-common', 'neqo-qpack', 'neqo-transport'):
            with self.subTest(name=name):
                changed = copy.deepcopy(cargo)
                next(p for p in changed['package'] if p['name'] == name)['source'] += '-drift'
                real_loads = tomllib.loads
                original = (build_neqo.CRATE / 'Cargo.lock').read_text()
                with mock.patch.object(build_neqo.tomllib, 'loads', side_effect=lambda text: changed if text == original else real_loads(text)):
                    with self.assertRaisesRegex(ValueError, name):
                        build_neqo.validate_lock(lock)
        changed = dict(lock, rust_toolchain='0.0.0')
        with self.assertRaisesRegex(ValueError, 'toolchain'):
            build_neqo.validate_lock(changed)

    def test_go_api_pin_drift_is_rejected(self):
        lock = json.loads(build_neqo.LOCK.read_text())
        actual = Path.read_text
        def read(path, *args, **kwargs):
            text = actual(path, *args, **kwargs)
            if path == build_neqo.ROOT / 'internal/neqo/api.go':
                text = text.replace(lock['neqo_commit'], '0' * 40)
            return text
        with mock.patch.object(Path, 'read_text', read):
            with self.assertRaisesRegex(ValueError, 'API Revision'):
                build_neqo.validate_lock(lock)

    def test_current_cargo_and_runtime_pins_agree(self):
        lock = json.loads(build_neqo.LOCK.read_text())
        build_neqo.validate_lock(lock)
        lock['neqo_commit'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'neqo-http3'):
            build_neqo.validate_lock(lock)

    def test_bad_download_does_not_replace_verified_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'nspr.deb'
            path.write_bytes(b'old')
            with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(b'bad archive')):
                with self.assertRaises(ValueError):
                    build_neqo.download('https://invalid.test/headers', path, '0' * 64)
            self.assertEqual(path.read_bytes(), b'old')
            self.assertFalse(path.with_suffix('.part').exists())

    def test_reuse_license_directory_exports_attribution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            crate = root / 'crate'
            (crate / 'LICENSES').mkdir(parents=True)
            (crate / 'LICENSES/MIT.txt').write_text('MIT license text')
            (crate / 'README.md').write_text('SPDX-FileCopyrightText: example author')
            metadata = {'resolve': {'nodes': [{'id': 'crate'}]}, 'packages': [{'id': 'crate', 'name': 'fixture', 'version': '1', 'license': 'MIT', 'manifest_path': str(crate / 'Cargo.toml'), 'source': None}]}
            out = root / 'out'
            out.mkdir()
            with mock.patch('subprocess.check_output', return_value=json.dumps(metadata).encode()):
                build_neqo.export_licenses(out, {})
            self.assertEqual((out / 'licenses/fixture-1/MIT.txt').read_text(), 'MIT license text')
            self.assertIn('author', (out / 'licenses/fixture-1/README.md').read_text())


if __name__ == '__main__':
    unittest.main()
