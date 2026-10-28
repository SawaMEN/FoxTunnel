#!/usr/bin/env python3
"""Build the opt-in Linux/amd64 bridge against hash-pinned Mozilla runtime.

No library download is performed by the running tunnel. Ordinary release builds
never call this script and do not contain this experimental backend.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import tomllib
import urllib.request

import mozilla_runtime

ROOT = Path(__file__).resolve().parents[1]
CRATE = ROOT / 'rust/neqo-bridge'
LOCK = ROOT / 'scripts/neqo.lock.json'


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def download(url, destination, expected):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and mozilla_runtime.digest(destination) == expected:
        return
    temp = destination.with_suffix('.part')
    try:
        with urllib.request.urlopen(url, timeout=120) as src, temp.open('wb') as dst:
            total = 0
            while data := src.read(1 << 20):
                total += len(data)
                if total > 16 << 20:
                    raise ValueError('NSPR headers exceed download bound')
                dst.write(data)
        mozilla_runtime.check_hash(temp, expected)
        os.replace(temp, destination)
    finally:
        temp.unlink(missing_ok=True)


def validate_lock(lock):
    patch = lock['source_patch']
    if patch['path'] != 'rust/patches/neqo-classic-connect-half-close.patch' or patch['source_path'] != 'neqo-http3/src/connection.rs':
        raise ValueError('unexpected Neqo source patch path')
    mozilla_runtime.check_hash(ROOT / patch['path'], patch['sha256'])
    cargo = tomllib.loads((CRATE / 'Cargo.lock').read_text())
    for name, key in [('neqo-http3', 'neqo'), ('nss-rs', 'nss_rs')]:
        packages = [p for p in cargo['package'] if p['name'] == name]
        if len(packages) != 1 or packages[0]['version'] != lock[key + '_version'] or not packages[0].get('source', '').endswith('#' + lock[key + '_commit']):
            raise ValueError('Cargo.lock does not match pinned ' + name)
    # Every Mozilla protocol crate must use the same source revision. Checking
    # only neqo-http3 misses transport/qpack/common drift in a modified lockfile.
    expected_source = ('git+https://github.com/mozilla/neqo?rev=' +
                       lock['neqo_commit'] + '#' + lock['neqo_commit'])
    for package in cargo['package']:
        source = package.get('source', '')
        if source.startswith('git+https://github.com/mozilla/neqo') and source != expected_source:
            raise ValueError('Cargo.lock does not match pinned ' + package['name'])
        if package['name'].startswith('neqo-'):
            if package['version'] != lock['neqo_version'] or package.get('source') != expected_source:
                raise ValueError('Cargo.lock does not match pinned ' + package['name'])
        if package['name'] == 'nss-rs' and source != 'git+https://github.com/mozilla/nss-rs#' + lock['nss_rs_commit']:
            raise ValueError('Cargo.lock does not match pinned nss-rs source')
    toolchain = tomllib.loads((CRATE / 'rust-toolchain.toml').read_text())
    if toolchain['toolchain']['channel'] != lock['rust_toolchain']:
        raise ValueError('Rust toolchain pin differs')
    manifest = tomllib.loads((CRATE / 'Cargo.toml').read_text())
    for name in ('neqo-common', 'neqo-http3', 'neqo-transport'):
        dependency = manifest['dependencies'][name]
        if dependency.get('git') != 'https://github.com/mozilla/neqo' or dependency.get('rev') != lock['neqo_commit']:
            raise ValueError('Cargo.toml does not match pinned ' + name)
    api = (ROOT / 'internal/neqo/api.go').read_text()
    for name, key in [('Version', 'neqo_version'), ('Revision', 'neqo_commit')]:
        match = re.search(r'^const ' + name + r' = "([^"]+)"$', api, re.MULTILINE)
        if match is None or match[1] != lock[key]:
            raise ValueError('Go Neqo API ' + name + ' pin differs')
    if lock['nss_version'] != json.loads(mozilla_runtime.LOCK.read_text())['nss_version']:
        raise ValueError('Neqo and TCP NSS runtime pins differ')


def validate_runtime(runtime):
    data = json.loads((runtime / 'mozilla-runtime.json').read_text())
    lock = json.loads(mozilla_runtime.LOCK.read_text())
    if data['nss_version'] != lock['nss_version'] or data['archive_sha256'] != lock['archives']['amd64']['sha256']:
        raise ValueError('unexpected Mozilla runtime provenance')
    if set(data['libraries']) != set(lock['libraries']):
        raise ValueError('incomplete Mozilla runtime')
    for name, expected in data['libraries'].items():
        mozilla_runtime.check_hash(runtime / 'lib' / name, expected)
    mozilla_runtime.inspect_libraries(runtime, lock['libraries'], 'amd64')


def apply_source_patch(source, patch, revision):
    """Patch only a pinned checkout in this build's private Cargo home.

    The unmodified Cargo.lock still identifies upstream. The separately pinned
    patch and both file hashes describe the exact change in build provenance.
    """
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if head != revision:
        raise ValueError('Neqo patch source revision differs')
    changes = subprocess.check_output(['git', '-C', str(source), 'diff', '--name-only', 'HEAD'], text=True).splitlines()
    if changes and changes != [patch['source_path']]:
        raise ValueError('unexpected changes in private Neqo checkout')
    target = source / patch['source_path']
    current = mozilla_runtime.digest(target)
    if current == patch['after_sha256']:
        return
    mozilla_runtime.check_hash(target, patch['before_sha256'])
    patch_file = ROOT / patch['path']
    mozilla_runtime.check_hash(patch_file, patch['sha256'])
    run(['git', '-C', source, 'apply', '--check', patch_file])
    run(['git', '-C', source, 'apply', patch_file])
    mozilla_runtime.check_hash(target, patch['after_sha256'])


def prepare_patched_neqo(out, env, lock):
    # Never alter another project's Cargo cache. Following cargo commands must
    # retain this home too, otherwise they could rebuild stock Neqo unnoticed.
    env['CARGO_HOME'] = str(out / 'cargo-home')
    run(['cargo', 'fetch', '--locked'], cwd=CRATE, env=env)
    matches = list((out / 'cargo-home/git/checkouts').glob('neqo-*/*/neqo-http3/src/connection.rs'))
    if len(matches) != 1:
        raise ValueError('expected one pinned Neqo checkout in private Cargo home')
    apply_source_patch(matches[0].parents[2], lock['source_patch'], lock['neqo_commit'])
    # Cargo fingerprints Git dependencies by revision, not local patch bytes.
    # Rebuild this crate on every preparation, including a reused build output.
    run(['cargo', 'clean', '-p', 'neqo-http3'], cwd=CRATE, env=env)


def source_headers(destination, commit):
    if not (destination / '.git').exists():
        destination.mkdir(parents=True, exist_ok=True)
        run(['git', 'init', '-q', destination])
        run(['git', '-C', destination, 'remote', 'add', 'origin', 'https://github.com/mozilla/nss.git'])
        run(['git', '-C', destination, 'fetch', '--depth=1', 'origin', commit])
        run(['git', '-C', destination, 'checkout', '--detach', commit])
    actual = subprocess.check_output(['git', '-C', str(destination), 'rev-parse', 'HEAD'], text=True).strip()
    if actual != commit or subprocess.check_output(['git', '-C', str(destination), 'status', '--porcelain']):
        raise ValueError('NSS headers must be an unmodified pinned checkout')
    return destination


def export_licenses(out, env):
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--format-version=1', '--filter-platform=x86_64-unknown-linux-gnu'], cwd=CRATE, env=env))
    selected = {node['id'] for node in metadata['resolve']['nodes']}
    packages = []
    for package in metadata['packages']:
        if package['id'] not in selected:
            continue
        name = package['name'] + '-' + package['version']
        base = Path(package['manifest_path']).parent
        license_files = []
        for directory in [base, *list(base.parents)[:3]]:
            found=[]
            for entry in directory.iterdir():
                if entry.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')):
                    if entry.is_file():found.append(entry)
                    elif entry.is_dir():found.extend(p for p in entry.rglob('*') if p.is_file())
            if found:
                license_files = found
                break
        if package.get('license_file'):
            license_path=Path(package['license_file'])
            license_files.append(license_path if license_path.is_absolute() else base / license_path)
        if not license_files:
            raise ValueError('missing license text for ' + name)
        target = out / 'licenses' / name
        target.mkdir(parents=True, exist_ok=True)
        for path in sorted(set(license_files)):
            if path.stat().st_size > 2 << 20:
                raise ValueError('oversized license file')
            shutil.copyfile(path, target / path.name)
        # Preserve authors/attribution where a REUSE-style crate puts generic
        # SPDX license texts in LICENSES and copyright notices in its README.
        for readme in base.glob('README*'):
            if readme.is_file() and readme.stat().st_size < 128 << 10:
                shutil.copyfile(readme,target / readme.name)
        packages.append(dict(name=package['name'], version=package['version'], license=package['license'], source=package['source']))
    (out / 'rust-dependencies.json').write_text(json.dumps(dict(schema=1, packages=packages), indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=CRATE / 'target/vetroff-build')
    parser.add_argument('--nss-source', type=Path)
    parser.add_argument('--mozilla-runtime', type=Path)
    parser.add_argument('--nspr-include', type=Path)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('initial Neqo build supports Linux amd64 only')
    lock = json.loads(LOCK.read_text())
    validate_lock(lock)
    version = subprocess.check_output(['rustc', '--version'], cwd=CRATE, text=True).split()[1]
    if version != lock['rust_toolchain']:
        raise ValueError('use pinned Rust ' + lock['rust_toolchain'])
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    runtime = args.mozilla_runtime.resolve() if args.mozilla_runtime else out / 'mozilla-runtime'
    if not (runtime / 'mozilla-runtime.json').exists():
        if args.mozilla_runtime:
            raise ValueError('provided runtime is missing provenance')
        mozilla_runtime.prepare('amd64', runtime)
    validate_runtime(runtime)
    headers = source_headers(args.nss_source.resolve() if args.nss_source else out / 'nss', lock['nss_headers_commit'])
    nspr = args.nspr_include.resolve() if args.nspr_include else out / 'nspr/usr/include/nspr'
    if not nspr.exists():
        if args.nspr_include:
            raise ValueError('NSPR include directory missing')
        archive = out / 'nspr-headers.deb'
        download(lock['nspr_headers_url'], archive, lock['nspr_headers_sha256'])
        run(['dpkg-deb', '-x', archive, out / 'nspr'])
    if '#define PR_VERSION  "4.39"' not in (nspr / 'prinit.h').read_text():
        raise ValueError('expected NSPR 4.39 headers')
    include = sorted({p.parent for p in (headers / 'lib').rglob('*.h')}) + [nspr]
    pc = out / 'pkgconfig'
    pc.mkdir(exist_ok=True)
    # Use public header declarations from the pinned checkout. Rust's bindgen
    # allowlist controls generated symbols; private .h folders are not vendored.
    (pc / 'nss.pc').write_text('Name: nss\nDescription: VetroffProxy pinned Mozilla NSS\nVersion: 3.130\nLibs: -L' + str(runtime / 'lib') + ' -lssl3 -lsmime3 -lnss3 -lnssutil3 -lplds4 -lplc4 -lnspr4\nCflags: ' + ' '.join('-I' + str(p) for p in include) + '\n')
    env = os.environ.copy()
    env['PKG_CONFIG_PATH'] = str(pc) + os.pathsep + env.get('PKG_CONFIG_PATH', '')
    env['LD_LIBRARY_PATH'] = str(runtime / 'lib') + os.pathsep + env.get('LD_LIBRARY_PATH', '')
    env['CGO_LDFLAGS'] = '-L' + str(runtime / 'lib') + ' ' + env.get('CGO_LDFLAGS', '')
    # Go's TCP bridge also probes nspr independently via pkg-config.
    (pc / 'nspr.pc').write_text('Name: nspr\nDescription: VetroffProxy pinned Mozilla NSPR\nVersion: 4.39\nLibs: -L' + str(runtime / 'lib') + ' -lplds4 -lplc4 -lnspr4\nCflags: -I' + str(nspr) + '\n')
    if env.get('CARGO_TARGET_DIR'):
        raise ValueError('unset CARGO_TARGET_DIR: the ABI link path is crate target/release')
    prepare_patched_neqo(out, env, lock)
    run(['cargo', 'build', '--locked', '--release'], cwd=CRATE, env=env)
    export_licenses(out, env)
    # Go's build cache does not watch external static archives. A local C
    # header makes the Rust archive part of the cgo package's source hash.
    archive_hash=mozilla_runtime.digest(CRATE / 'target/release/libfoxtunnel_neqo.a')
    (ROOT / 'internal/neqo/build_stamp.h').write_text('#define FT_NEQO_ARCHIVE_SHA256 "' + archive_hash + '"\n')
    selected = {key: env[key] for key in ['PKG_CONFIG_PATH', 'LD_LIBRARY_PATH', 'CGO_LDFLAGS', 'CARGO_HOME']}
    (out / 'env.sh').write_text(''.join('export ' + key + '=' + shlex.quote(value) + '\n' for key, value in selected.items()))
    (out / 'provenance.json').write_text(json.dumps(dict(schema=1, **{k: v for k, v in lock.items() if k != 'schema'}), indent=2) + '\n')
    print('Built experimental Neqo ABI 2; source ' + str(out / 'env.sh') + ' before Go -tags nss,neqo builds/tests. No release published.')


if __name__ == '__main__':
    main()
