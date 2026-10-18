import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import release


class ReleaseContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = argparse.Namespace(input=str(self.root), version='v0.1.0-alpha.1', targets=None)
        self.entries = []
        for n, target in enumerate(sorted(release.TARGETS)):
            suffix = '.zip' if target.startswith('windows/') else '.tar.gz'
            name = 'foxtunnel_0.1.0-alpha.1_' + target.replace('/', '_') + suffix
            data = f'fixture-{target}'.encode()
            (self.root / name).write_bytes(data)
            p = dict(schema=1, version=self.args.version, commit='a' * 40, dirty=False, target=target, filename=name, sha256=hashlib.sha256(data).hexdigest(), size=len(data))
            meta = self.root / (name + '.metadata.json')
            meta.write_text(json.dumps(p))
            self.entries.append(meta)

    def edit(self, key, value):
        path = self.entries[0]
        p = json.loads(path.read_text())
        p[key] = value
        path.write_text(json.dumps(p))

    def test_complete_index_and_no_overwrite(self):
        release.index(self.args)
        self.assertEqual(9, len(json.loads((self.root / 'manifest.json').read_text())['artifacts']))
        self.assertEqual(10, len((self.root / 'SHA256SUMS').read_text().splitlines()))
        with self.assertRaises(FileExistsError):
            release.index(self.args)

    def test_corruption_rejected(self):
        p = json.loads(self.entries[0].read_text())
        (self.root / p['filename']).write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            release.index(self.args)

    def test_incomplete_rejected(self):
        self.entries[0].unlink()
        with self.assertRaises(ValueError):
            release.index(self.args)

    def test_dirty_rejected(self):
        self.edit('dirty', True)
        with self.assertRaises(ValueError):
            release.index(self.args)

    def test_mixed_commit_rejected(self):
        self.edit('commit', 'b' * 40)
        with self.assertRaises(ValueError):
            release.index(self.args)

    def test_path_escape_rejected(self):
        self.edit('filename', '../outside')
        with self.assertRaises(ValueError):
            release.index(self.args)

    def test_version_contract(self):
        for good in ['v0.1.0-alpha.1', 'v1.2.3', 'v1.2.3-rc-1']:
            release.validate_version(good)
        for bad in ['1.2.3', 'v01.0.0', 'v1.2.3-..', 'v1.2.3-01', 'v1.2.3/other']:
            with self.assertRaises(ValueError):
                release.validate_version(bad)


if __name__ == '__main__':
    unittest.main()
