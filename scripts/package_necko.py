#!/usr/bin/env python3
"""Create an immutable Linux amd64/ARM64 Necko helper bundle from a verified build.

The output is a new directory. Updates use a new version directory, never an
in-place overwrite of a running runtime. A manifest detects corruption and API
mismatch, not publisher identity; distribute the archive SHA256 through trusted CI.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile

from necko_platform import verify_elf

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    with path.open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def package(runtime, provenance, launcher, out, cli=None):
    if out.resolve().is_relative_to(runtime.resolve()):
        raise ValueError('bundle destination must be outside runtime')
    if out.exists():
        raise ValueError('bundle destination already exists')
    source = ROOT / 'experiments/firefox-necko/gecko.lock.json'
    helper = ROOT / 'experiments/firefox-necko/client.js'
    record = json.loads(provenance.read_text())
    if (record.get('status') != 'built-not-interop-tested' or
            record.get('source') != json.loads(source.read_text())):
        raise ValueError('runtime source lock differs from helper')
    target = record.get('target_platform', 'linux-amd64')
    if target not in record['source'].get('platforms', [record['source'].get('platform')]):
        raise ValueError('unsupported runtime platform')
    for name in ('xpcshell', 'libxul.so', 'libnss3.so'):
        verify_elf(runtime / name, target)
    if (runtime / 'firefox').exists():
        verify_elf(runtime / 'firefox', target)
    verify_elf(launcher, target)
    if cli is not None:
        verify_elf(cli, target)
    for name in ('xpcshell', 'libxul.so', 'libnss3.so', 'platform.ini'):
        if digest(runtime / name) != record['runtime'].get(name):
            raise ValueError('compiled runtime digest mismatch: ' + name)
    if not launcher.is_file() or launcher.is_symlink():
        raise ValueError('regular compiled launcher required')
    # Source-build dist/bin has links into obj directories. Use the dereferenced
    # CI runtime artifact rather than silently copying arbitrary external files.
    for path in runtime.rglob('*'):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('runtime must contain regular files/directories only')
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.necko-package-', dir=out.parent) as tmp:
        staging = Path(tmp) / 'bundle'
        staging.mkdir(mode=0o700)
        shutil.copytree(runtime, staging / 'runtime')
        if cli is not None:
            if not cli.is_file() or cli.is_symlink():
                raise ValueError('regular compiled CLI required')
            shutil.copyfile(cli, staging / 'vetroff')
            (staging / 'vetroff').chmod(0o755)
        shutil.copyfile(launcher, staging / 'foxtunnel-necko')
        (staging / 'foxtunnel-necko').chmod(0o755)
        shutil.copyfile(provenance, staging / 'provenance.json')
        shutil.copyfile(source, staging / 'source-lock.json')
        (staging / 'licenses').mkdir()
        shutil.copyfile(ROOT / 'LICENSE', staging / 'licenses/VetroffProxy-MIT.txt')
        shutil.copyfile(ROOT / 'experiments/firefox-necko/LICENSES.go.txt', staging / 'licenses/Go-dependencies.txt')
        shutil.copyfile(ROOT / 'experiments/firefox-necko/LICENSE.mozilla', staging / 'licenses/Mozilla.txt')
        shutil.copyfile(ROOT / 'experiments/firefox-necko/LICENSES.mozilla.html', staging / 'licenses/Mozilla.html')
        shutil.copytree(ROOT / 'experiments/firefox-necko/patches', staging / 'source-patches')
        lock = record['source']
        (staging / 'SOURCE.txt').write_text(
            'Mozilla runtime source: ' + lock['repository'] + '\nRevision: ' + lock['revision'] +
            '\nApply the included source-patches according to source-lock.json.\n'
            'Helper source: https://github.com/SawaMEN/FoxTunnel/tree/main/experiments/firefox-necko\n'
            'This bundle is an opt-in experimental ' + target + ' distribution.\n')
        files = {p.relative_to(staging).as_posix(): digest(p)
                 for p in sorted(staging.rglob('*')) if p.is_file()}
        manifest = dict(schema=1, helper_protocol=1, platform=target,
                        source_lock_sha256=digest(source), client_js_sha256=digest(helper), files=files)
        (staging / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        os.rename(staging, out)
    return manifest


def archive(bundle, destination):
    if destination.resolve().is_relative_to(bundle.resolve()):
        raise ValueError('archive must be outside bundle')
    with destination.open('xb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|') as tar:
                for path in [bundle, *sorted(bundle.rglob('*'))]:
                    info = tar.gettarinfo(path, arcname='foxtunnel-necko' if path == bundle else 'foxtunnel-necko/' + path.relative_to(bundle).as_posix())
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    if path.is_file():
                        with path.open('rb') as src:
                            tar.addfile(info, src)
                    else:
                        tar.addfile(info)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--provenance', type=Path, required=True)
    parser.add_argument('--launcher', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--cli', type=Path, help='main VetroffProxy CLI with owned Necko engine')
    args = parser.parse_args()
    if args.archive and args.archive.exists():
        parser.error('archive destination already exists')
    package(args.runtime.resolve(), args.provenance, args.launcher, args.out, args.cli)
    if args.archive:
        archive(args.out, args.archive)
        print(digest(args.archive), args.archive.name)
    print('Bundle created:', args.out)


if __name__ == '__main__':
    main()
