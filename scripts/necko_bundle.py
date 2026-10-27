"""Verify a Necko directory offline before combining or installing it."""
from pathlib import Path, PurePosixPath
import stat

import release_verify as contract
from necko_platform import MACHINES, verify_elf

FIELDS = {'schema', 'helper_protocol', 'platform', 'source_lock_sha256',
          'client_js_sha256', 'files'}
REQUIRED = {'runtime/xpcshell', 'runtime/libxul.so', 'runtime/libnss3.so',
            'runtime/platform.ini', 'provenance.json', 'source-lock.json',
            'foxtunnel-necko'}


def verify(directory, platform=None, source=None, client=None):
    directory = Path(directory)
    manifest = contract.read_json(directory / 'manifest.json')
    target = manifest.get('platform')
    if (set(manifest) != FIELDS or type(manifest.get('schema')) is not int or
            manifest['schema'] != 1 or type(manifest.get('helper_protocol')) is not int or
            manifest['helper_protocol'] != 1 or target not in MACHINES or
            (platform is not None and target != platform)):
        raise ValueError('incompatible Necko manifest/platform')
    hashes = manifest['files']
    if not isinstance(hashes, dict) or not 1 <= len(hashes) <= 20000 or not REQUIRED <= hashes.keys():
        raise ValueError('incomplete Necko file manifest')
    for name, digest in hashes.items():
        if (not isinstance(name, str) or not name or '\\' in name or
                PurePosixPath(name).is_absolute() or
                any(p in ('', '.', '..') for p in name.split('/')) or
                not isinstance(digest, str) or not contract.HASH.fullmatch(digest)):
            raise ValueError('invalid Necko manifest member')
    observed = {}
    for path in directory.rglob('*'):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or mode & 0o7000:
            raise ValueError('links/privileged modes forbidden in Necko bundle')
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError('nonregular Necko member')
        if path == directory / 'manifest.json':
            continue
        observed[path.relative_to(directory).as_posix()] = contract.sha(path)
        with path.open('rb') as stream:
            if stream.read(4) == b'\x7fELF':
                verify_elf(path, target)
    if observed != hashes:
        raise ValueError('Necko bundle manifest mismatch')
    for name in ('foxtunnel-necko', 'runtime/xpcshell', 'runtime/libxul.so', 'runtime/libnss3.so',
                 *[n for n in ('foxtunnel', 'lib/libnss3.so') if n in observed]):
        verify_elf(directory / name, target)
    for field in ('source_lock_sha256', 'client_js_sha256'):
        if not isinstance(manifest[field], str) or not contract.HASH.fullmatch(manifest[field]):
            raise ValueError('invalid Necko source digest')
    if observed['source-lock.json'] != manifest['source_lock_sha256']:
        raise ValueError('Gecko source lock digest mismatch')
    lock = contract.read_json(directory / 'source-lock.json')
    provenance = contract.read_json(directory / 'provenance.json')
    if (provenance.get('status') != 'built-not-interop-tested' or
            provenance.get('target_platform', 'linux-amd64') != target or
            not contract.same_json(provenance.get('source'), lock)):
        raise ValueError('Necko provenance/source/platform mismatch')
    for name in ('xpcshell', 'libxul.so', 'libnss3.so', 'platform.ini'):
        if provenance.get('runtime', {}).get(name) != observed['runtime/' + name]:
            raise ValueError('Necko runtime provenance digest mismatch')
    if source is not None and (contract.sha(source) != manifest['source_lock_sha256'] or
                               not contract.same_json(contract.read_json(source), lock)):
        raise ValueError('Necko source differs from this release')
    if client is not None and contract.sha(client) != manifest['client_js_sha256']:
        raise ValueError('Necko helper differs from this release')
    return manifest
