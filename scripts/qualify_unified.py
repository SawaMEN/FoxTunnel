#!/usr/bin/env python3
"""Qualify actual unified archives and reversible native installation on CI."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

import deploy_cli
import merge_necko_nss as merge
import necko_bundle
from necko_platform import host_platform
import release_verify as contract
import unified_archive

ROOT = Path(__file__).resolve().parents[1]


def qualify(a):
    if host_platform() != 'linux-' + a.arch:
        raise ValueError('unified native qualification requires its own architecture')
    # Verify the NSS archive independently, before executing its CLI.
    contract.verify(argparse.Namespace(input=str(a.nss.parent), version=a.version,
                                      commit=a.commit, target='linux/'+a.arch+'/nss'))
    with tempfile.TemporaryDirectory(prefix='vetroff-unified-check-') as tmp:
        root = Path(tmp)
        unpacked = root / 'bundle'
        unpacked.mkdir()
        nss = unified_archive.unpack(a.archive, unpacked, a.version, a.commit)
        manifest = necko_bundle.verify(unpacked, 'linux-'+a.arch,
                                      ROOT/'experiments/firefox-necko/gecko.lock.json',
                                      ROOT/'experiments/firefox-necko/client.js')
        replica = root / 'repeat.tar.gz'
        if merge.make_archive(unpacked, replica) != merge.sha(a.archive):
            raise ValueError('unified archive is not reproducible from verified contents')
    manager = deploy_cli.Deployment(a.install)
    before = manager.install(a.nss, deploy_cli.digest(a.nss), a.version, a.commit, archive=True)
    record = manager.install(a.archive, deploy_cli.digest(a.archive), a.version, a.commit, archive=True)
    if manager.rollback()['identity'] != before['identity']:
        raise ValueError('unified rollback did not restore NSS-only installation')
    again = manager.install(a.archive, deploy_cli.digest(a.archive), a.version, a.commit, archive=True)
    if again != record:
        raise ValueError('immutable unified reinstall changed its installation record')
    executable, installed = manager.bundle(record['identity'])
    bundle = executable.parent
    info = json.loads(subprocess.check_output([str(executable), 'version', '--json'], timeout=15))
    if (info.get('version') != a.version or info.get('commit') != a.commit or
            info.get('goarch') != a.arch or info.get('dirty') is not False or
            info.get('build_flavor') != 'nss' or
            info.get('nss_version') != nss['runtime']['mozilla']['nss_version'] or
            not {'necko', 'mozilla', 'legacy'} <= set(info.get('transport_engines', []))):
        raise ValueError('actual combined binary differs from source/version/backends')
    subprocess.run([str(bundle/'foxtunnel-necko'), '--bundle', str(bundle), '--verify'],
                   timeout=60, check=True)
    result = dict(schema=1, status='verified-before-transfer-gates', platform='linux-'+a.arch,
                  version=a.version, commit=a.commit, archive=a.archive.name,
                  archive_sha256=merge.sha(a.archive), archive_bytes=a.archive.stat().st_size,
                  manifest_files=len(manifest['files']), source_lock_sha256=manifest['source_lock_sha256'],
                  client_js_sha256=manifest['client_js_sha256'], installed_bundle=str(bundle),
                  checks=['offline-full-manifest', 'all-ELF-architectures', 'NSS-input-contract',
                          'exact-Necko-source-and-helper', 'deterministic-archive', 'native-build-identity',
                          'NSS-install', 'unified-install', 'rollback', 'immutable-reinstall',
                          'native-helper-verification'], binary=info,
                  scope='Actual archived and installed files; transfer gates run next on this installed bundle.')
    with a.report.open('x') as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write('\n')
    return result


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('archive','nss','install','report'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--version',required=True)
    p.add_argument('--commit',required=True)
    p.add_argument('--arch',choices=('amd64','arm64'),required=True)
    a=p.parse_args()
    result=qualify(a)
    print('Verified native unified archive:',result['archive'],result['archive_sha256'])
