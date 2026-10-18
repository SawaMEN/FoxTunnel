#!/usr/bin/env python3
"""Build four Linux release archives and validate them without extra index assets."""
import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import mozilla_runtime
from release_verify import TARGETS, validate_version, validate_manifest, read_json, inspect_archive, verify

ROOT = Path(__file__).resolve().parents[1]


def command(args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env, text=True).strip()


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def new_file(path, content):
    with path.open('xb') as f:
        f.write(content)


def licenses(go, env):
    cmd = [go, 'list', '-buildvcs=false', '-mod=readonly', '-deps', '-json']
    if env['CGO_ENABLED'] == '1':
        cmd += ['-tags', 'nss']
    raw = command(cmd + ['./cmd/foxtunnel'], env)
    modules, decoder = {}, json.JSONDecoder()
    while raw:
        pkg, end = decoder.raw_decode(raw)
        raw = raw[end:].lstrip()
        m = pkg.get('Module')
        if m and not m.get('Main'):
            modules[m['Path']] = m
    goroot = Path(command([go, 'env', 'GOROOT'], env))
    files = {'LICENSE': (ROOT / 'LICENSE').read_bytes(), 'licenses/Go-LICENSE': (goroot / 'LICENSE').read_bytes()}
    notices = ['FoxTunnel: MIT, see LICENSE.', 'Go runtime: licenses/Go-LICENSE.']
    for name, module in sorted(modules.items()):
        base, found = Path(module.get('Replace', module)['Dir']), False
        for filename in ('LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING'):
            path = base / filename
            if path.is_file():
                dest = 'licenses/' + name.replace('/', '_') + '-' + filename
                files[dest] = path.read_bytes()
                notices.append(f"{name} {module['Version']}: {dest}")
                found = True
        if not found:
            raise ValueError('missing linked-module license: ' + name)
    if env['CGO_ENABLED'] == '1':
        notices.append('Unmodified Mozilla NSS/NSPR/SQLite libraries are bundled in lib/. See licenses/Mozilla-about-license.html for their licenses and notices. Source form is available at the exact URL and SHA-256 in mozilla-runtime.json; those libraries are not covered by FoxTunnel MIT LICENSE.')
    files['THIRD_PARTY_NOTICES.txt'] = ('\n'.join(notices) + '\n').encode()
    return files


def build(a):
    validate_version(a.version)
    target = f'{a.os}/{a.arch}/{a.backend}'
    if target not in TARGETS:
        raise ValueError('unsupported target: ' + target)
    commit = command(['git', 'rev-parse', 'HEAD'])
    dirty = bool(command(['git', 'status', '--porcelain', '--untracked-files=normal']))
    if dirty and not a.allow_dirty:
        raise ValueError('dirty tree; commit first or use --allow-dirty only for local testing')
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', command(['git', 'show', '-s', '--format=%ct', 'HEAD'])))
    date = dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    env = os.environ.copy()
    env.update(GOOS=a.os, GOARCH=a.arch, GOAMD64='v1', CGO_ENABLED='1' if a.backend == 'nss' else '0', GOWORK='off', GOFLAGS='')
    host = json.loads(command([a.go, 'env', '-json', 'GOHOSTOS', 'GOHOSTARCH'], env))
    go_version = command([a.go, 'env', 'GOVERSION'], env)
    native = host['GOHOSTOS'] == env['GOOS'] and host['GOHOSTARCH'] == env['GOARCH']
    if a.backend == 'nss' and not native:
        raise ValueError('NSS requires a native Linux runner for the selected architecture')
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    ext = '.tar.gz'
    archive = out / f'foxtunnel_{a.version[1:]}_{a.os}_{a.arch}_{a.backend}{ext}'
    metadata = out / (archive.name + '.metadata.json')
    if archive.exists() or metadata.exists():
        raise ValueError('refusing to replace an existing versioned artifact')
    variant = ''
    fields = {'Version': a.version, 'Commit': commit, 'BuildDate': date, 'Variant': variant, 'Dirty': str(dirty).lower()}
    ldflags = '-s -w -buildid= ' + ' '.join('-X github.com/SawaMEN/FoxTunnel/internal/buildinfo.' + k + '=' + v for k, v in fields.items())
    with tempfile.TemporaryDirectory(prefix='foxtunnel-release-') as tmp:
        runtime_files, runtime_info = {}, {}
        if a.backend == 'nss':
            runtime_files, runtime_info = mozilla_runtime.prepare(a.arch, tmp, a.mozilla_archive)
            env['CGO_LDFLAGS'] = env.get('CGO_LDFLAGS', '') + ' -Wl,--disable-new-dtags -Wl,-rpath,$ORIGIN/lib'
        executable = Path(tmp) / 'foxtunnel'
        cmd = [a.go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags', ldflags, '-o', str(executable)]
        if a.backend == 'nss':
            cmd += ['-tags', 'nss']
        subprocess.run(cmd + ['./cmd/foxtunnel'], cwd=ROOT, env=env, check=True)
        info = {}
        if a.backend == 'nss':
            env = mozilla_runtime.verify_loaded(executable, Path(tmp), runtime_info['libraries'], env)
        if native:
            info = json.loads(command([str(executable), 'version', '--json'], env))
            for k, v in dict(version=a.version, commit=commit, goos=a.os, goarch=env['GOARCH'], go_version=go_version, build_flavor=a.backend, dirty=dirty, protocol_draft='foxtunnel-draft-0', default_tls_backend='go').items():
                if info[k] != v:
                    raise ValueError('native metadata mismatch: ' + k)
        if a.backend == 'nss' and info.get('nss_version') != runtime_info['nss_version']:
            raise ValueError('loaded NSS version differs from pinned Mozilla runtime')
        files = licenses(a.go, env)
        files.update(runtime_files)
        p = dict(schema=1, version=a.version, commit=commit, build_date=date, target=target, goos=a.os, goarch=env['GOARCH'], variant=variant, build_flavor=a.backend, dirty=dirty, protocol_draft='foxtunnel-draft-0', experimental=True, native_smoke_tested=native)
        p['go_version'] = go_version
        p['tls_backends'] = ['go', 'nss'] if a.backend == 'nss' else ['go']
        p['default_tls_backend'] = 'go'
        p['runtime'] = dict(kind='bundled-nss', baseline=a.baseline, packages=['glibc', 'libgcc-s1'], mozilla=runtime_info) if a.backend == 'nss' else dict(kind='cgo-disabled')
        if info.get('nss_version'):
            p['runtime']['nss_version'] = info['nss_version']
        files['build.json'] = (json.dumps(p, indent=2) + '\n').encode()
        files[executable.name] = executable.read_bytes()
        with archive.open('xb') as f, gzip.GzipFile(filename='', mode='wb', fileobj=f, mtime=epoch) as gz, tarfile.open(fileobj=gz, mode='w') as tar:
            for name, data in sorted(files.items()):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mtime = len(data), epoch
                entry.mode = 0o755 if name == executable.name else 0o644
                tar.addfile(entry, io.BytesIO(data))
    p.update(filename=archive.name, sha256=sha(archive), size=archive.stat().st_size)
    new_file(metadata, (json.dumps(p, indent=2) + '\n').encode())
    print(json.dumps(dict(artifact=archive.name, sha256=p['sha256'], native_smoke_tested=native)))


def index(a):
    """Validate the complete local Linux release set without writing extra assets."""
    validate_version(a.version)
    base, packages = Path(a.input), []
    expected = set(a.targets.split(',')) if a.targets else TARGETS
    if not expected or not expected <= TARGETS:
        raise ValueError('unsupported index target set')
    for path in sorted(base.glob('*.metadata.json')):
        packages.append(read_json(path))
    commit = packages[0].get('commit') if packages else None
    release_set = dict(schema=1, version=a.version, commit=commit,
                       protocol_draft='foxtunnel-draft-0', artifacts=packages)
    validate_manifest(release_set, a.version, commit, expected)
    for p in packages:
        inspect_archive(base / p['filename'], p)
    print(f'Validated {len(packages)} Linux archives from {commit}; no index files written')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    b = sub.add_parser('build')
    for flag in ('version', 'os', 'arch', 'backend'):
        b.add_argument('--' + flag, required=True)
    b.add_argument('--go', default='go')
    b.add_argument('--out', default='dist')
    b.add_argument('--baseline', default='native-host')
    b.add_argument('--mozilla-archive', help='offline Firefox archive; pinned hash is always checked')
    b.add_argument('--allow-dirty', action='store_true')
    i = sub.add_parser('index')
    i.add_argument('--version', required=True)
    i.add_argument('--input', default='dist')
    i.add_argument('--targets', help='test subset; release CI requires all four Linux targets')
    v = sub.add_parser('verify', help='verify downloaded release assets without extracting or executing them')
    v.add_argument('--version', required=True, help='exact expected tag from a trusted source')
    v.add_argument('--commit', required=True, help='expected full source commit from a trusted source')
    v.add_argument('--input', default='dist')
    v.add_argument('--target', help='verify one Linux archive without requiring the other three')
    a = parser.parse_args()
    try:
        {'build': build, 'index': index, 'verify': verify}[a.command](a)
    except (ValueError, KeyError, OSError, EOFError, tarfile.TarError, subprocess.CalledProcessError) as e:
        parser.exit(1, str(e) + '\n')


if __name__ == '__main__':
    main()
