import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import capture_native_wire as capture


class PinnedWireInputs(unittest.TestCase):
    def test_archive_digest_checked_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'archive'
            with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(b'not the pinned binary')):
                with self.assertRaisesRegex(ValueError, 'digest'):
                    capture.download('https://invalid.test/file', p, '0'*64, 1024)

    def test_archive_download_has_size_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch('urllib.request.urlopen', return_value=io.BytesIO(b'x'*20)):
                with self.assertRaisesRegex(ValueError, 'bound'):
                    capture.download('https://invalid.test/file', Path(tmp)/'archive', '0'*64, 10)


if __name__ == '__main__':
    unittest.main()
