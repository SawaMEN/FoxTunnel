import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from necko_platform import host_platform, verify_elf


class PlatformTests(unittest.TestCase):
    def test_native_hosts_and_unsupported_hosts(self):
        for machine, target in [('x86_64', 'linux-amd64'), ('amd64', 'linux-amd64'),
                                ('aarch64', 'linux-arm64'), ('arm64', 'linux-arm64')]:
            with patch('necko_platform.platform.machine', return_value=machine), patch('necko_platform.sys.platform', 'linux'):
                self.assertEqual(host_platform(), target)
        for machine, system in [('armv7l', 'linux'), ('aarch64', 'darwin')]:
            with patch('necko_platform.platform.machine', return_value=machine), patch('necko_platform.sys.platform', system):
                with self.assertRaises(ValueError):
                    host_platform()

    def test_elf_rejects_wrong_class_endianness_version_and_machine(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'binary'
            header = bytearray(64)
            header[:7] = b'\x7fELF\x02\x01\x01'
            struct.pack_into('<HHI', header, 16, 3, 183, 1)
            path.write_bytes(header)
            verify_elf(path, 'linux-arm64')
            for target in ('linux-amd64', 'linux-386'):
                with self.assertRaises(ValueError):
                    verify_elf(path, target)
            for offset in (0, 4, 5, 6, 16, 18, 20):
                broken = bytearray(header)
                broken[offset] = 0
                path.write_bytes(broken)
                with self.assertRaises(ValueError):
                    verify_elf(path, 'linux-arm64')
            path.write_bytes(header[:32])
            with self.assertRaises(ValueError):
                verify_elf(path, 'linux-arm64')
