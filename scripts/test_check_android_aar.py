"""Offline tests for Android arm64 release archive verification."""
import io
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

import check_android_aar


def make_aar(path, machine=183, include_class=True, extra_abi=False):
    elf = bytearray(64)
    elf[:4] = bytes([127, 69, 76, 70])
    elf[4:6] = bytes([2, 1])
    struct.pack_into("<H", elf, 18, machine)
    java = io.BytesIO()
    with zipfile.ZipFile(java, "w") as jar:
        if include_class:
            jar.writestr("com/vetroff/androidsdk/Session.class", b"dummy")
    with zipfile.ZipFile(path, "w") as aar:
        aar.writestr("classes.jar", java.getvalue())
        aar.writestr("jni/arm64-v8a/libgojni.so", bytes(elf))
        if extra_abi:
            aar.writestr("jni/armeabi-v7a/libgojni.so", bytes(elf))


class AndroidAARTests(unittest.TestCase):
    def test_valid_arm64(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "valid.aar"
            make_aar(path)
            check_android_aar.check(path)

    def test_rejects_wrong_elf_architecture(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "wrong.aar"
            make_aar(path, machine=62)
            with self.assertRaisesRegex(ValueError, "AArch64"):
                check_android_aar.check(path)

    def test_rejects_multiple_native_abis(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "multi.aar"
            make_aar(path, extra_abi=True)
            with self.assertRaisesRegex(ValueError, "only arm64"):
                check_android_aar.check(path)

    def test_rejects_missing_java_binding(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "noapi.aar"
            make_aar(path, include_class=False)
            with self.assertRaisesRegex(ValueError, "Session"):
                check_android_aar.check(path)


if __name__ == "__main__":
    unittest.main()
