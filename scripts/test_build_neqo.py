import io
import copy
import json
from pathlib import Path
import tempfile
import unittest
import tomllib
from unittest import mock

import build_neqo


class NeqoBuildIntegrity(unittest.TestCase):
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
