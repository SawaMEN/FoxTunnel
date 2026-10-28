#!/usr/bin/env python3
"""Build a versioned Linux/amd64 VetroffProxy Mozilla bundle (Go + NSS + Neqo).

This is a separate, opt-in build artifact, NOT a GitHub Release. All inputs
must be locked; the script never changes release requests or tags.
It builds without running test suites or invoking the built VetroffProxy binary.
"""
import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile

import build_neqo
import mozilla_runtime
import release
from release_verify import safe_name, validate_version

ROOT = Path(__file__).resolve().parents[1]
MAX_ASSET_SIZE = 150 * 1024 * 1024
MAX_BUNDLE_SIZE = 256 * 1024 * 1024


def run(argv, env=None):
    subprocess.run([str(v) for v in argv], cwd=ROOT, env=env, check=True)


def required_bytes(path, limit=MAX_ASSET_SIZE):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError('missing, unsafe or oversized build input: ' + str(path))
    return path.read_bytes()


def append_asset(files, name, content):
    safe_name(name)
    if name in files or not 0 < len(content) <= MAX_ASSET_SIZE:
        raise ValueError('duplicate/empty/oversized bundle entry: ' + name)
    files[name] = content


def rust_licenses(root):
    """Flatten Cargo attribution into portable archive paths with an index."""
    root = Path(root)
    paths = sorted(p for p in root.glob('*/*') if p.is_file())
    if not paths:
        raise ValueError('missing Rust dependency license inventory')
    files = {}
    inventory = {}
    for i, path in enumerate(paths):
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError('symlink in Rust license inventory')
        name = f'licenses/Rust-{i:04d}.txt'
        append_asset(files, name, required_bytes(path, 2 * 1024 * 1024))
        inventory[name] = str(path.relative_to(root)).replace(os.sep, '/')
    append_asset(files, 'rust-license-index.json', (json.dumps(
        {'schema': 1, 'entries': inventory}, indent=2, sort_keys=True) + '\n').encode())
    return files


def package(argv):
    validate_version(argv.version)
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('Mozilla bundle currently requires a native Linux amd64 host')
    if os.environ.get('CARGO_TARGET_DIR'):
        raise ValueError('unset CARGO_TARGET_DIR (pinned bridge expects crate target/release)')
    commit = release.command(['git', 'rev-parse', 'HEAD'])
    if release.command(['git', 'status', '--porcelain', '--untracked-files=normal']):
        raise ValueError('refusing to package a dirty source tree')
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', release.command(
        ['git', 'show', '-s', '--format=%ct', 'HEAD'])))
    build_date = dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    out = Path(argv.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    stem = f'vetroffproxy_{argv.version[1:]}_linux_amd64_mozilla.tar.gz'
    archive = out / stem
    metadata_file = out / (stem + '.metadata.json')
    if archive.exists() or metadata_file.exists():
        raise ValueError('refusing to replace an existing Mozilla build')
    with tempfile.TemporaryDirectory(prefix='foxtunnel-mozilla-bundle-') as d:
        staging = Path(d)
        runtime_files, runtime = mozilla_runtime.prepare('amd64', staging, argv.mozilla_archive)
        native_out = staging / 'native'
        run([sys.executable, ROOT / 'scripts/build_neqo.py',
             '--out', native_out, '--mozilla-runtime', staging])
        lock = json.loads(build_neqo.LOCK.read_text())
        build_neqo.validate_lock(lock)
        provenance = required_bytes(native_out / 'provenance.json', 4 * 1024 * 1024)
        expected = dict(schema=1, **{k: v for k, v in lock.items() if k != 'schema'})
        if json.loads(provenance) != expected:
            raise ValueError('Neqo build provenance differs from pinned lock')
        dependency_manifest = required_bytes(native_out / 'rust-dependencies.json', 4 * 1024 * 1024)
        if json.loads(dependency_manifest).get('schema') != 1:
            raise ValueError('invalid Rust dependency inventory')
        env = os.environ.copy()
        env.update(GOOS='linux', GOARCH='amd64', GOAMD64='v1', CGO_ENABLED='1',
                   GOWORK='off', GOFLAGS='')
        env['PKG_CONFIG_PATH'] = str(native_out / 'pkgconfig') + os.pathsep + env.get('PKG_CONFIG_PATH', '')
        env['LD_LIBRARY_PATH'] = str(staging / 'lib') + os.pathsep + env.get('LD_LIBRARY_PATH', '')
        env['CGO_LDFLAGS'] = ('-L' + str(staging / 'lib') +
                             ' -Wl,--disable-new-dtags -Wl,-rpath,$ORIGIN/lib ' +
                             env.get('CGO_LDFLAGS', ''))
        values = {'Version': argv.version, 'Commit': commit, 'BuildDate': build_date,
                  'Variant': '', 'Dirty': 'false'}
        ldflags = '-s -w -buildid= ' + ' '.join(
            '-X github.com/SawaMEN/FoxTunnel/internal/buildinfo.' + key + '=' + val
            for key, val in values.items())
        executable = staging / 'vetroffproxy'
        run([argv.go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false',
             '-tags', 'nss,neqo,mozilla', '-ldflags', ldflags,
             '-o', executable, './cmd/vetroffproxy'], env=env)
        # Dependency checks do not run the target executable or any test suite.
        mozilla_runtime.verify_loaded(executable, staging, runtime['libraries'], env)
        go_version = release.command([argv.go, 'env', 'GOVERSION'], env)
        if not go_version.startswith('go'):
            raise ValueError('cannot identify Go compiler')
        files = release.licenses(argv.go, env)
        files.update(release.integration_files())
        for name, content in runtime_files.items():
            if name in files:
                raise ValueError('duplicate runtime asset: ' + name)
            append_asset(files, name, content)
        for name, content in rust_licenses(native_out / 'licenses').items():
            append_asset(files, name, content)
        append_asset(files, 'neqo-provenance.json', provenance)
        append_asset(files, 'rust-dependencies.json', dependency_manifest)
        append_asset(files, 'vetroffproxy', required_bytes(executable))
        notices = files['THIRD_PARTY_NOTICES.txt'].decode()
        notices += ('Pinned Neqo 0.33.0 / Rust dependencies: rust-dependencies.json, '
                    'neqo-provenance.json and licenses/Rust-*.txt (mapped by rust-license-index.json).\n')
        files['THIRD_PARTY_NOTICES.txt'] = notices.encode()
        asset_hashes = {name: hashlib.sha256(content).hexdigest()
                        for name, content in sorted(files.items()) if name != 'build.json'}
        meta = dict(
            schema=1, product='protocol-core', integration_schema=1,
            version=argv.version, commit=commit, build_date=build_date,
            target='linux/amd64/mozilla', goos='linux', goarch='amd64',
            build_flavor='mozilla', protocol_draft='foxtunnel-draft-0', experimental=True,
            engine='mozilla', default_engine='legacy', go_version=go_version,
            tls_backends=['go', 'nss'], quic_backends=['quic-go', 'neqo'],
            nss_version=runtime['nss_version'], neqo_version=lock['neqo_version'],
            neqo_revision=lock['neqo_commit'], rust_toolchain=lock['rust_toolchain'],
            native_compiled=True, tests_run=False, binary_executed=False,
            runtime=dict(kind='bundled-mozilla', baseline='ubuntu-24.04',
                         packages=['glibc', 'libgcc-s1'], mozilla=runtime,
                         neqo_provenance_sha256=hashlib.sha256(provenance).hexdigest(),
                         rust_dependencies_sha256=hashlib.sha256(dependency_manifest).hexdigest()),
            asset_sha256=asset_hashes)
        append_asset(files, 'build.json', (json.dumps(meta, indent=2, sort_keys=True) + '\n').encode())
        if len(files) > 1024 or sum(map(len, files.values())) > MAX_BUNDLE_SIZE:
            raise ValueError('Mozilla bundle exceeds archive safety limits')
        with archive.open('xb') as f:
            with gzip.GzipFile(fileobj=f, mode='wb', filename='', mtime=epoch) as gz:
                with tarfile.open(fileobj=gz, mode='w') as tar:
                    for name, content in sorted(files.items()):
                        item = tarfile.TarInfo(name)
                        item.size = len(content)
                        item.mtime = epoch
                        item.mode = 0o755 if name == 'vetroffproxy' else 0o644
                        tar.addfile(item, io.BytesIO(content))
    result = dict(schema=1, artifact=stem, version=argv.version,
                  target='linux/amd64/mozilla', commit=commit,
                  sha256=release.sha(archive), size=archive.stat().st_size,
                  tests_run=False, published=False)
    metadata_file.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--out', default='dist')
    parser.add_argument('--mozilla-archive', help='offline Firefox archive; SHA-256 pin is always enforced')
    args = parser.parse_args()
    try:
        package(args)
    except (ValueError, KeyError, OSError, EOFError, tarfile.TarError,
            subprocess.CalledProcessError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
