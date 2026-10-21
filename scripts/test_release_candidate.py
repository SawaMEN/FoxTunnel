import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import release_candidate as candidate
import release_notes
import test_release


class CandidateEvidence(unittest.TestCase):
    def data(self, missing=False):
        rows = []
        for name in candidate.PAYLOAD_CASES:
            rows.extend([dict(Package=candidate.PACKAGE, Action='run', Test=name),
                         dict(Package=candidate.PACKAGE, Action='skip' if missing else 'pass', Test=name)])
        rows.append(dict(Package=candidate.PACKAGE, Action='pass'))
        return b'\n'.join(json.dumps(row).encode() for row in rows)

    def test_requires_both_actual_payload_cases(self):
        self.assertTrue(candidate.events(self.data(), candidate.PAYLOAD_CASES)['passed'])
        with self.assertRaisesRegex(ValueError, 'skipped'):
            candidate.events(self.data(True), candidate.PAYLOAD_CASES)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            candidate.events(b'', candidate.PAYLOAD_CASES)

    def test_legacy_hash_checked_before_executable_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(b'bad')):
                with self.assertRaisesRegex(ValueError, 'digest'):
                    candidate.fetch_legacy(dict(filename='old.tar.gz', url='https://invalid.test', size=3, sha256='0'*64), Path(tmp))
            self.assertFalse((Path(tmp)/'foxtunnel-legacy').exists())

    def test_legacy_archive_links_are_not_extracted(self):
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w:gz') as archive:
            info=tarfile.TarInfo('foxtunnel');info.type=tarfile.SYMTYPE;info.linkname='/outside'
            archive.addfile(info)
        data=raw.getvalue()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch('urllib.request.urlopen',return_value=io.BytesIO(data)):
                with self.assertRaisesRegex(ValueError,'unsafe'):
                    candidate.fetch_legacy(dict(filename='old.tar.gz',url='https://invalid.test',size=len(data),sha256=hashlib.sha256(data).hexdigest()),Path(tmp))
            self.assertFalse((Path(tmp)/'foxtunnel-legacy').exists())

    def test_notes_require_complete_verified_archives(self):
        fixture=test_release.ReleaseContract();fixture.setUp();self.addCleanup(fixture.doCleanups)
        text=release_notes.render(fixture.root,fixture.args.version,'a'*40,'Release candidate')
        for path in fixture.entries:
            row=json.loads(path.read_text())
            self.assertIn(row['sha256'],text)
        fixture.pack(0, mutate=lambda files: files.update({'lib/libnss3.so': b'tampered'}))
        with self.assertRaisesRegex(ValueError, 'library hash'):
            release_notes.render(fixture.root, fixture.args.version, 'a'*40, 'Release candidate')
