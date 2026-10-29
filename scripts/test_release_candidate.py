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

    def test_notes_require_complete_verified_archives(self):
        fixture=test_release.ReleaseContract();fixture.setUp();self.addCleanup(fixture.doCleanups)
        text=release_notes.render(fixture.root,fixture.args.version,'a'*40,'Release candidate')
        for path in fixture.entries:
            row=json.loads(path.read_text())
            self.assertIn(row['sha256'],text)
        fixture.pack(0, mutate=lambda files: files.update({'lib/libnss3.so': b'tampered'}))
        with self.assertRaisesRegex(ValueError, 'library hash'):
            release_notes.render(fixture.root, fixture.args.version, 'a'*40, 'Release candidate')
