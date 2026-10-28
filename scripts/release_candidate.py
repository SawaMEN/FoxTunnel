#!/usr/bin/env python3
"""Exercise verified native NSS bundles and a pinned published legacy binary.

Only private temporary installations and loopback Go test fixtures are used.
No release is published, configuration reused, or production listener started.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request
import urllib.error

import deploy_cli
import release_verify as contract
from private_files import write_exclusive

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'scripts/release-compat.lock.json'
MAX_EVENTS = 8 << 20
PACKAGE = 'example.com/independent-vetroff-consumer'
PAYLOAD_CASES = {'TestReleaseProcessHost/h2-connect', 'TestReleaseProcessHost/h3-post'}
LEGACY_CASES = {'TestWireLegacyBinaryCompatibility/legacy-compatible-server',
                'TestWireLegacyBinaryCompatibility/strict-server'}


def require(value, message):
    if not value:
        raise ValueError(message)


def events(data, expected):
    require(len(data) <= MAX_EVENTS, 'test events exceed limit')
    started, passed, package_passed = set(), set(), False
    for line in data.splitlines():
        row = contract.json_object(line)
        require(row.get('Package') == PACKAGE and row.get('Action') != 'fail', 'test package failed')
        name, action = row.get('Test'), row.get('Action')
        if name in expected:
            require(action != 'skip', 'required release test skipped')
            if action == 'run':
                require(name not in started, 'duplicate test run')
                started.add(name)
            if action == 'pass':
                require(name in started and name not in passed, 'pass without one run')
                passed.add(name)
        elif name is None and action == 'pass':
            package_passed = True
    require(package_passed and started == passed == expected, 'incomplete release test matrix')
    return dict(passed=True, executed_required_cases=sorted(passed),
                test_event_sha256=hashlib.sha256(data).hexdigest())


def run_tests(go, name, expected, env):
    with tempfile.TemporaryFile() as output:
        result = subprocess.run([go, 'test', '-race', '-json', './...', '-run', '^' + name + '$',
                                 '-count=1', '-timeout=90s'], cwd=ROOT / 'integration/external',
                                env=env, stdout=output, stderr=subprocess.STDOUT, timeout=240)
        output.seek(0)
        data = output.read(MAX_EVENTS + 1)
    require(result.returncode == 0, 'packaged binary integration failed (private logs omitted)')
    return events(data, expected)


def fetch_legacy(item, folder):
    archive = folder / item['filename']
    with urllib.request.urlopen(item['url'], timeout=60) as response, archive.open('xb') as output:
        total = 0
        while block := response.read(1 << 20):
            total += len(block)
            require(total <= item['size'] <= 16 << 20, 'legacy download exceeds pin')
            output.write(block)
    require(total == item['size'] and deploy_cli.digest(archive) == item['sha256'], 'legacy digest mismatch')
    executable = folder / 'vetroff-legacy'
    total, count, seen = 0, 0, set()
    with tarfile.open(archive, 'r|gz') as source:
        for entry in source:
            contract.safe_name(entry.name)
            count += 1
            total += entry.size
            require(entry.isfile() and entry.name not in seen and count <= contract.MAX_MEMBERS
                    and 0 <= entry.size <= contract.MAX_MEMBER and total <= contract.MAX_TOTAL,
                    'unsafe legacy archive')
            seen.add(entry.name)
            if entry.name == 'vetroff':
                with source.extractfile(entry) as input_file, executable.open('xb') as output:
                    while block := input_file.read(1 << 20):
                        output.write(block)
    require(executable.is_file(), 'legacy executable absent')
    executable.chmod(0o700)
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('primary', 'replica', 'upgrade', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    require(not args.out.exists(), 'output must be new')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT), 'dirty source tree')
    goos, arch = deploy_cli.target()
    require(goos == 'linux' and arch in ('amd64', 'arm64'), 'requires a native supported Linux runner')
    primary = contract.embedded_metadata(args.primary)
    upgrade = contract.embedded_metadata(args.upgrade)
    contract.validate_metadata(primary, args.version, args.commit)
    contract.validate_metadata(upgrade, upgrade['version'], args.commit)
    require(primary['goarch'] == upgrade['goarch'] == arch, 'non-native archive')
    require(upgrade['version'] != primary['version'], 'upgrade version must differ')
    contract.inspect_archive(args.primary, primary)
    contract.inspect_archive(args.upgrade, upgrade)
    require(deploy_cli.digest(args.primary) == deploy_cli.digest(args.replica), 'independent build bytes differ')
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(('FOXTUNNEL_', 'FOX_')) or key.startswith('LD_'):
            del env[key]
    results = []
    lock = contract.read_json(LOCK)
    with tempfile.TemporaryDirectory(prefix='vetroff-release-gate-') as tmp:
        work = Path(tmp)
        manager = deploy_cli.Deployment(work / 'installation')
        config = manager.config / 'preserved-profile'
        config.write_bytes(b'isolated-profile-must-not-change')
        config.chmod(0o600)
        config_before = (deploy_cli.digest(config), config.stat().st_mode)
        for phase, archive, metadata in [('install', args.primary, primary), ('update', args.upgrade, upgrade),
                                          ('rollback', args.primary, primary)]:
            if phase == 'rollback':
                record = manager.rollback()
            else:
                record = manager.install(archive, metadata['sha256'], metadata['version'], args.commit, archive=True)
            require(manager.state()['active'] == record['identity'] == metadata['sha256'], 'wrong activation')
            executable, _ = manager.bundle(record['identity'])
            trial = dict(env, FOX_RELEASE_PROCESS_BINARY=str(executable))
            result = run_tests(args.go, 'TestReleaseProcessHost', PAYLOAD_CASES, trial)
            require((deploy_cli.digest(config), config.stat().st_mode) == config_before, 'private config changed')
            results.append(dict(phase=phase, archive_sha256=record['identity'], version=record['version'], **result))
        published_legacy_passed = False
        try:
            legacy = fetch_legacy(lock['artifacts'][arch], work)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            # The originally pinned alpha.1 artifact was removed from Releases.
            # Never substitute an unpinned download or claim wire interoperability
            # passed. The independently checked native install/update/rollback
            # matrix above is mandatory even while the old artifact is missing.
            compatibility = dict(passed=False, unavailable=True, reason='pinned historical release asset HTTP 404')
            print('::warning::Pinned historical Go release asset unavailable; legacy wire test NOT VERIFIED')
        else:
            info = contract.json_object(subprocess.check_output([str(legacy), 'version', '--json'], env=env, timeout=10))
            for key, expected in dict(schema=1, version=lock['tag'], commit=lock['source_commit'],
                                      goos=goos, goarch=arch, build_flavor='go', protocol_draft=contract.DRAFT, dirty=False).items():
                require(type(info.get(key)) is type(expected) and info[key] == expected, 'legacy executable identity mismatch')
            compatibility = run_tests(args.go, 'TestWireLegacyBinaryCompatibility', LEGACY_CASES,
                                      dict(env, FOXTUNNEL_LEGACY_BINARY=str(legacy)))
            published_legacy_passed = compatibility['passed']
    toolchain = {name: subprocess.check_output(command, env=env, text=True).splitlines()[0]
                 for name, command in {'go': [args.go, 'version'], 'cc': ['cc', '--version'],
                                       'ld': ['ld', '--version'], 'nss_headers': ['pkg-config', '--modversion', 'nss']}.items()}
    report = dict(schema=1, kind='native-release-candidate', source_commit=args.commit,
                  toolchain=toolchain, nss_runtime=primary['runtime']['nss_version'],
                  legacy_lock_sha256=hashlib.sha256(LOCK.read_bytes()).hexdigest(),
                  native_platform=goos, native_arch=arch, worktree_dirty=False, passed=True,
                  primary={k: primary[k] for k in ('filename', 'sha256', 'size', 'version', 'go_version')},
                  reproducible_archive_sha256=deploy_cli.digest(args.replica),
                  deployment=results, configuration_preserved=True,
                  legacy=dict(version=lock['tag'], source_commit=lock['source_commit'],
                              archive_sha256=lock['artifacts'][arch]['sha256'], **compatibility),
                  scope='Same-source/toolchain native Linux loopback. H2 uses installed bundled NSS, H3 quic-go. '
                        'Published legacy Go archive tests TCP/H2 in both directions and strict refusal. '
                        'No cross-host bit reproducibility, WAN, third-party integration or signed-release claim.')
    write_exclusive(args.out, json.dumps(report, indent=2, sort_keys=True) + '\n', 0o600)
    print(json.dumps(dict(passed=True, native_arch=arch, deployment_cases=6, published_legacy_passed=published_legacy_passed,
                          reproducible_archive_sha256=report['reproducible_archive_sha256'])))


if __name__ == '__main__':
    main()
