#!/usr/bin/env python3
"""Validate the packaged Android AAR JNI ABI and generated bindings."""
import io
from pathlib import Path
import struct
import sys
import zipfile

def check(path):
    with zipfile.ZipFile(path) as aar:
        entries = aar.namelist()
        libraries = [n for n in entries if n.startswith("jni/") and n.endswith(".so")]
        if libraries != ["jni/arm64-v8a/libgojni.so"]:
            raise ValueError("expected only arm64-v8a libgojni.so; got " + str(libraries))
        if "classes.jar" not in entries:
            raise ValueError("missing Java API")
        elf = aar.read(libraries[0])
        if elf[:4] != bytes([127, 69, 76, 70]) or elf[4] != 2 or elf[5] != 1:
            raise ValueError("not ELF64 little-endian")
        if struct.unpack_from("<H", elf, 18)[0] != 183:
            raise ValueError("JNI binary is not AArch64")
        with zipfile.ZipFile(io.BytesIO(aar.read("classes.jar"))) as jar:
            if not any(n.endswith("/Session.class") for n in jar.namelist()):
                raise ValueError("missing Session binding")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_android_aar.py FILE.aar")
    check(Path(sys.argv[1]))
