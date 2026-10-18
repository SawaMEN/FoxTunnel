#!/usr/bin/env python3
"""Build immutable release archives and verify a complete version index."""
import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = set('linux/amd64/go linux/arm64/go linux/armv7/go darwin/amd64/go darwin/arm64/go windows/amd64/go windows/arm64/go linux/amd64/nss linux/arm64/nss'.split())
VERSION = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z')


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
        notices.append('NSS/NSPR are dynamically linked, not bundled. Install libnss3/libnspr4. Mozilla sources/licenses: https://firefox-source-docs.mozilla.org/security/nss/ ; https://www.mozilla.org/MPL/2.0/')
    files['THIRD_PARTY_NOTICES.txt'] = ('\n'.join(notices) + '\n').encode()
    return files


def validate_version(version):
    if not VERSION.fullmatch(version):
        raise ValueError('version must be a v-prefixed semantic version')
    if '-' in version:
        for identifier in version.split('-', 1)[1].split('.'):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith('0'):
                raise ValueError('numeric prerelease identifiers cannot have leading zeros')


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
    env.update(GOOS=a.os, GOARCH='arm' if a.arch == 'armv7' else a.arch, GOARM='7', GOAMD64='v1', CGO_ENABLED='1' if a.backend == 'nss' else '0', GOWORK='off', GOFLAGS='')
    host = json.loads(command([a.go, 'env', '-json', 'GOHOSTOS', 'GOHOSTARCH'], env))
    native = host['GOHOSTOS'] == env['GOOS'] and host['GOHOSTARCH'] == env['GOARCH']
    if a.backend == 'nss' and not native:
        raise ValueError('NSS requires a native Linux runner for the selected architecture')
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    ext = '.zip' if a.os == 'windows' else '.tar.gz'
    archive = out / f'foxtunnel_{a.version[1:]}_{a.os}_{a.arch}_{a.backend}{ext}'
    metadata = out / (archive.name + '.metadata.json')
    if archive.exists() or metadata.exists():
        raise ValueError('refusing to replace an existing versioned artifact')
    variant = '7' if a.arch == 'armv7' else ''
    fields = {'Version': a.version, 'Commit': commit, 'BuildDate': date, 'Variant': variant, 'Dirty': str(dirty).lower()}
    ldflags = '-s -w -buildid= ' + ' '.join('-X github.com/SawaMEN/FoxTunnel/internal/buildinfo.' + k + '=' + v for k, v in fields.items())
    with tempfile.TemporaryDirectory(prefix='foxtunnel-release-') as tmp:
        executable = Path(tmp) / ('foxtunnel.exe' if a.os == 'windows' else 'foxtunnel')
        cmd = [a.go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags', ldflags, '-o', str(executable)]
        if a.backend == 'nss':
            cmd += ['-tags', 'nss']
        subprocess.run(cmd + ['./cmd/foxtunnel'], cwd=ROOT, env=env, check=True)
        info = {}
        if native:
            info = json.loads(command([str(executable), 'version', '--json'], env))
            for k, v in dict(version=a.version, commit=commit, goos=a.os, goarch=env['GOARCH'], build_flavor=a.backend, dirty=dirty, protocol_draft='foxtunnel-draft-0', default_tls_backend='go').items():
                if info[k] != v:
                    raise ValueError('native metadata mismatch: ' + k)
        files = licenses(a.go, env)
        p = dict(schema=1, version=a.version, commit=commit, build_date=date, target=target, goos=a.os, goarch=env['GOARCH'], variant=variant, build_flavor=a.backend, dirty=dirty, protocol_draft='foxtunnel-draft-0', experimental=True, native_smoke_tested=native)
        p['tls_backends'] = ['go', 'nss'] if a.backend == 'nss' else ['go']
        p['default_tls_backend'] = 'go'
        p['runtime'] = dict(kind='dynamic', baseline=a.baseline, packages=['libnss3', 'libnspr4']) if a.backend == 'nss' else dict(kind='cgo-disabled')
        if info.get('nss_version'):
            p['runtime']['nss_version'] = info['nss_version']
        files['build.json'] = (json.dumps(p, indent=2) + '\n').encode()
        files[executable.name] = executable.read_bytes()
        if ext == '.zip':
            with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED) as z:
                stamp = dt.datetime.fromtimestamp(max(epoch, 315532800), dt.timezone.utc).timetuple()[:6]
                for name, data in sorted(files.items()):
                    entry = zipfile.ZipInfo(name, date_time=stamp)
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    entry.external_attr = (0o100755 if name == executable.name else 0o100644) << 16
                    z.writestr(entry, data)
        else:
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
    validate_version(a.version)
    base, packages, seen, commit = Path(a.input), [], set(), None
    expected = set(a.targets.split(',')) if a.targets else TARGETS
    for path in sorted(base.glob('*.metadata.json')):
        p = json.loads(path.read_text())
        name = p['filename']
        if Path(name).name != name or not name.startswith('foxtunnel_'):
            raise ValueError('invalid archive filename')
        parts = p['target'].split('/')
        if len(parts) != 3:
            raise ValueError('invalid target')
        suffix = '.zip' if parts[0] == 'windows' else '.tar.gz'
        expected_name = 'foxtunnel_' + a.version[1:] + '_' + '_'.join(parts) + suffix
        if name != expected_name:
            raise ValueError('archive filename does not match target/version')
        archive = base / name
        if p['schema'] != 1 or p['version'] != a.version or p['dirty']:
            raise ValueError('mixed version/schema or dirty build')
        if p['target'] in seen or p['target'] not in expected:
            raise ValueError('duplicate/unexpected target')
        seen.add(p['target'])
        if p['sha256'] != sha(archive) or p['size'] != archive.stat().st_size:
            raise ValueError('archive hash/size mismatch')
        if commit is not None and p['commit'] != commit:
            raise ValueError('mixed source commits')
        commit = p['commit']
        packages.append(p)
    if seen != expected:
        raise ValueError('incomplete release target set: ' + str(expected - seen))
    manifest = dict(schema=1, version=a.version, commit=commit, protocol_draft='foxtunnel-draft-0', artifacts=packages)
    new_file(base / 'manifest.json', (json.dumps(manifest, indent=2) + '\n').encode())
    sums = ''.join(p['sha256'] + '  ' + p['filename'] + '\n' for p in packages)
    sums += sha(base / 'manifest.json') + '  manifest.json\n'
    new_file(base / 'SHA256SUMS', sums.encode())
    print(f'Verified {len(packages)} artifacts from {commit}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    b = sub.add_parser('build')
    for flag in ('version', 'os', 'arch', 'backend'):
        b.add_argument('--' + flag, required=True)
    b.add_argument('--go', default='go')
    b.add_argument('--out', default='dist')
    b.add_argument('--baseline', default='native-host')
    b.add_argument('--allow-dirty', action='store_true')
    i = sub.add_parser('index')
    i.add_argument('--version', required=True)
    i.add_argument('--input', default='dist')
    i.add_argument('--targets', help='test subset; release CI requires all nine targets')
    a = parser.parse_args()
    try:
        (build if a.command == 'build' else index)(a)
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as e:
        parser.exit(1, str(e) + '\n')


if __name__ == '__main__':
    main()
