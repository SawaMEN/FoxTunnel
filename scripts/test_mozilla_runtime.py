import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import mozilla_runtime as runtime


class MozillaArchiveIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / 'mozilla.tar.xz'
        self.out = self.root / 'out'
        self.out.mkdir()

    def make(self, entries):
        with tarfile.open(self.archive, 'w:xz') as tar:
            for name, kind, data in entries:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.size = len(data) if kind == tarfile.REGTYPE else 0
                member.linkname = '../../outside' if kind == tarfile.SYMTYPE else ''
                tar.addfile(member, io.BytesIO(data))

    def test_only_expected_member_is_extracted(self):
        self.make([('../../outside', tarfile.REGTYPE, b'bad'), ('firefox/libnss3.so', tarfile.REGTYPE, b'good')])
        runtime.extract_members(self.archive, self.out, {'firefox/libnss3.so': 'lib/libnss3.so'})
        self.assertEqual((self.out / 'lib/libnss3.so').read_bytes(), b'good')
        self.assertEqual(list(self.out.rglob('*')), [self.out / 'lib', self.out / 'lib/libnss3.so'])

    def test_link_duplicate_and_missing_rejected(self):
        for entries in [
            [('firefox/libnss3.so', tarfile.SYMTYPE, b'')],
            [('firefox/libnss3.so', tarfile.REGTYPE, b'a')] * 2,
            [('firefox/other', tarfile.REGTYPE, b'a')],
        ]:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as out:
                self.make(entries)
                with self.assertRaises(ValueError):
                    runtime.extract_members(self.archive, Path(out), {'firefox/libnss3.so': 'libnss3.so'})

    def test_modified_archive_rejected(self):
        self.archive.write_bytes(b'original')
        expected = hashlib.sha256(b'original').hexdigest()
        runtime.check_hash(self.archive, expected)
        self.archive.write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            runtime.check_hash(self.archive, expected)

    def test_wrong_architecture_rejected(self):
        (self.out / 'lib').mkdir()
        (self.out / 'lib/libnss3.so').write_bytes(b'\x7fELF\x02\x01' + b'\0' * 12 + (183).to_bytes(2, 'little'))
        with self.assertRaisesRegex(ValueError, 'architecture'):
            runtime.inspect_libraries(self.out, ['libnss3.so'], 'amd64')


if __name__ == '__main__':
    unittest.main()
