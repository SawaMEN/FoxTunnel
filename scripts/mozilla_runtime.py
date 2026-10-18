#!/usr/bin/env python3
"""Prepare hash-pinned, unmodified Mozilla libraries for a native Linux release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'scripts/mozilla-runtime.lock.json'
# glibc and the compiler unwind runtime are supplied by the host. NSS crypto modules also need mozsqlite3.
SYSTEM_LIBS = {'libgcc_s.so.1', 'libc.so.6', 'libm.so.6', 'libpthread.so.0', 'libdl.so.2',
               'librt.so.1', 'libresolv.so.2', 'ld-linux-x86-64.so.2', 'ld-linux-aarch64.so.1'}
LICENSE_MEMBER = 'chrome/toolkit/content/global/license.html'


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def check_hash(path, expected):
    if digest(path) != expected:
        raise ValueError('Mozilla archive SHA-256 mismatch')


def extract_members(archive, destination, names):
    """Extract only expected regular files, never tar links or arbitrary paths."""
    seen = set()
    with tarfile.open(archive, 'r|xz') as tar:
        for member in tar:
            if member.name not in names:
                continue
            if member.name in seen or not member.isfile() or not 0 < member.size <= 150 * 1024 * 1024:
                raise ValueError('invalid/duplicate Mozilla archive member: ' + member.name)
            seen.add(member.name)
            target = destination / names[member.name]
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as src, target.open('xb') as dst:
                while block := src.read(1024 * 1024):
                    dst.write(block)
    if seen != set(names):
        raise ValueError('missing Mozilla archive members: ' + str(set(names) - seen))


def inspect_libraries(base, libraries, arch):
    for name in libraries:
        path = base / 'lib' / name
        header = path.read_bytes()[:20]
        machine = 62 if arch == 'amd64' else 183
        if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != machine:
            raise ValueError('wrong Mozilla ELF architecture: ' + name)
        dynamic = subprocess.check_output(['readelf', '-d', str(path)], text=True)
        needed = set(re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic))
        if needed - set(libraries) - SYSTEM_LIBS:
            raise ValueError('unbundled Mozilla dependency: ' + str(needed - set(libraries) - SYSTEM_LIBS))
        if '(RPATH)' in dynamic or '(RUNPATH)' in dynamic:
            raise ValueError('unexpected Mozilla library search path: ' + name)


def prepare(arch, destination, archive=None):
    lock = json.loads(LOCK.read_text())
    spec = lock['archives'][arch]
    out = Path(destination)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='foxtunnel-mozilla-') as tmp:
        tmp = Path(tmp)
        if archive:
            archive = Path(archive)
        else:
            archive = tmp / 'firefox.tar.xz'
            with urllib.request.urlopen(lock['base_url'] + spec['path'], timeout=120) as src, archive.open('xb') as dst:
                total = 0
                while block := src.read(1024 * 1024):
                    total += len(block)
                    if total > 250 * 1024 * 1024:
                        raise ValueError('Mozilla archive exceeds size limit')
                    dst.write(block)
        check_hash(archive, spec['sha256'])
        names = {'firefox/' + name: 'lib/' + name for name in lock['libraries']}
        names['firefox/omni.ja'] = 'omni.ja'
        extract_members(archive, tmp, names)
        inspect_libraries(tmp, lock['libraries'], arch)
        # Firefox uses an optimized ZIP layout: unzip returns warning/error status 1 or 2
        # while successfully extracting its complete, unmodified license page.
        license_result = subprocess.run(['unzip', '-p', str(tmp / 'omni.ja'), LICENSE_MEMBER], capture_output=True)
        if license_result.returncode not in (0, 1, 2) or not 10000 < len(license_result.stdout) < 2 * 1024 * 1024 or hashlib.sha256(license_result.stdout).hexdigest() != lock['license_sha256']:
            raise ValueError('cannot extract Mozilla license notices')
        files = {'lib/' + name: (tmp / 'lib' / name).read_bytes() for name in lock['libraries']}
        files['licenses/Mozilla-about-license.html'] = license_result.stdout
        provenance = dict(schema=1, firefox_version=lock['firefox_version'], nss_version=lock['nss_version'],
                          archive_url=lock['base_url'] + spec['path'], archive_sha256=spec['sha256'],
                          source_url=lock['base_url'] + lock['source']['path'], source_sha256=lock['source']['sha256'],
                          libraries={name: hashlib.sha256(files['lib/' + name]).hexdigest() for name in lock['libraries']})
        files['mozilla-runtime.json'] = (json.dumps(provenance, indent=2) + '\n').encode()
        for name, data in files.items():
            path = out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as f:
                f.write(data)
    return files, provenance


def verify_loaded(executable, base, libraries, env):
    clean = env.copy()
    for name in ('LD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_AUDIT'):
        clean.pop(name, None)
    dynamic = subprocess.check_output(['readelf', '-d', str(executable)], env=clean, text=True)
    if '(RPATH)' not in dynamic or '[$ORIGIN/lib]' not in dynamic or '(RUNPATH)' in dynamic:
        raise ValueError('NSS executable must use transitive $ORIGIN/lib RPATH')
    # Also inspect dlopen-only crypto modules, not just the executable's DT_NEEDED.
    for path in [executable] + [base / 'lib' / name for name in libraries]:
        probe_env = clean if path == executable else dict(clean, LD_LIBRARY_PATH=str(base / 'lib'))
        loaded = subprocess.check_output(['ldd', str(path)], env=probe_env, text=True)
        if 'not found' in loaded:
            raise ValueError('unresolved NSS runtime dependency')
        for name, resolved in re.findall(r'^\s*(\S+) => (\S+)', loaded, re.M):
            if name in libraries and Path(resolved).resolve() != (base / 'lib' / name).resolve():
                raise ValueError('NSS resolved outside release directory: ' + name)
    return clean


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--archive', help='offline archive; the pinned SHA-256 is still mandatory')
    args = parser.parse_args()
    _, info = prepare(args.arch, args.out, args.archive)
    print(json.dumps(info, indent=2))
