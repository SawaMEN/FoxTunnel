"""Publish verified archives, or replace an explicitly identified mutable release.

Stage both uploads before touching published names. Restore the previous assets,
tag and notes if promotion fails; never delete the previous release upfront.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from release_verify import validate_version


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True).strip()


def publish(version, commit, source, replace_commit, notes, directory):
    validate_version(version)
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('invalid source commit')
    archives = sorted(directory.glob('*.tar.gz'))
    expected = {f'vetroff_{version.removeprefix("v")}_linux_{arch}.tar.gz' for arch in ('amd64', 'arm64')}
    if {p.name for p in archives} != expected:
        raise ValueError('exactly two architecture archives are required')
    if source not in ('request', 'tag', 'replacement'):
        raise ValueError('unsupported release source')
    if source != 'replacement':
        if replace_commit:
            raise ValueError('replacement commit requires replacement mode')
        if source == 'request':
            tags = json.loads(gh('api', f'repos/{{owner}}/{{repo}}/git/matching-refs/tags/{version}'))
            if any(item['ref'] == 'refs/tags/' + version for item in tags):
                raise ValueError('release request must not reuse an existing tag')
        flags = ['--verify-tag'] if source == 'tag' else ['--target', commit]
        gh('release', 'create', version, *map(str, archives), *flags,
           '--prerelease' if '-' in version else '--latest', '--title', f'VetroffProxy {version}',
           '--notes-file', str(notes))
        return
    if not re.fullmatch(r'[0-9a-f]{40}', replace_commit) or replace_commit == commit:
        raise ValueError('replacement requires a different exact previous commit')
    repository = gh('repo', 'view', '--json', 'nameWithOwner', '--jq', '.nameWithOwner')
    prefix = f'repos/{repository}'
    release = json.loads(gh('api', f'{prefix}/releases/tags/{version}'))
    if release.get('immutable') or release['draft'] or release['tag_name'] != version:
        raise ValueError('only the requested mutable published release may be replaced')
    ref_path = f'{prefix}/git/refs/tags/{version}'

    def check_ref():
        ref = json.loads(gh('api', ref_path))
        if ref['object']['type'] != 'commit' or ref['object']['sha'] != replace_commit:
            raise ValueError('release tag changed or does not match replace_commit')

    check_ref()
    previous = {a['name']: a['id'] for a in release['assets']}
    if set(previous) != expected:
        raise ValueError('unexpected published assets; refusing replacement')
    staged = {}
    backups = []
    promoted = []
    moved = False
    try:
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for archive in archives:
                path = Path(tmp) / (archive.name + '.pending.' + commit)
                shutil.copyfile(archive, path)
                paths.append(str(path))
            gh('release', 'upload', version, *paths)
        assets = json.loads(gh('api', f'{prefix}/releases/{release["id"]}/assets'))
        staged = {a['name'].split('.pending.')[0]: a['id'] for a in assets
                  if a['name'].endswith('.pending.' + commit)}
        if set(staged) != expected:
            raise ValueError('staged archive uploads are incomplete')
        check_ref()
        for name, asset_id in previous.items():
            gh('api', '--method', 'PATCH', f'{prefix}/releases/assets/{asset_id}',
               '-f', 'name=' + name + '.previous.' + replace_commit)
            backups.append(name)
        for name, asset_id in staged.items():
            gh('api', '--method', 'PATCH', f'{prefix}/releases/assets/{asset_id}', '-f', 'name=' + name)
            promoted.append(name)
        gh('api', '--method', 'PATCH', ref_path, '-f', 'sha=' + commit, '-F', 'force=true')
        moved = True
        gh('release', 'edit', version, '--target', commit, '--title', f'VetroffProxy {version}',
           '--notes-file', str(notes))
    except Exception:
        # Keep the old release usable if promotion fails. Cleanup errors remain visible.
        for name in promoted:
            gh('api', '--method', 'PATCH', f'{prefix}/releases/assets/{staged[name]}',
               '-f', 'name=' + name + '.pending.' + commit)
        for name in backups:
            gh('api', '--method', 'PATCH', f'{prefix}/releases/assets/{previous[name]}', '-f', 'name=' + name)
        if moved:
            gh('api', '--method', 'PATCH', ref_path, '-f', 'sha=' + replace_commit, '-F', 'force=true')
        raise
    # Previous binaries survive until both archives, the tag and notes are promoted.
    for asset_id in previous.values():
        gh('api', '--method', 'DELETE', f'{prefix}/releases/assets/{asset_id}')
    print(f'Published {version} from {commit}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ('version', 'commit', 'source', 'notes', 'input'):
        parser.add_argument('--' + field, required=True, type=Path if field in ('notes', 'input') else str)
    parser.add_argument('--replace-commit', default='')
    args = parser.parse_args()
    publish(args.version, args.commit, args.source, args.replace_commit, args.notes, args.input)
