#!/usr/bin/env python3
"""Offline, per-user VetroffProxy deployment with verified staging and rollback.

Accepts a locally reviewed Go binary or an existing Linux NSS release archive.
The expected SHA-256 must come from a trusted source; hashes are NOT signatures.
Does not download, install services, modify OS routes, or overwrite configuration.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

import release_verify as contract
import unified_archive


def regular(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('expected regular file, not a symlink or special file')


def private_dir(path):
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('deployment directory cannot be a symlink or file')
    if os.name != 'nt' and (info.st_mode & 0o077 or info.st_uid != os.geteuid()):
        raise ValueError('deployment directories must be owner-only and owned by the operator')


def target():
    goos = {'Linux': 'linux', 'Darwin': 'darwin', 'Windows': 'windows'}.get(platform.system())
    arch = {'x86_64': 'amd64', 'AMD64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(platform.machine())
    if not goos or not arch:
        raise ValueError('unsupported native platform')
    return goos, arch


def digest(path):
    regular(path)
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sync_directory(path):
    if os.name != 'nt':
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def sync_bundle(path):
    # Persist contents and their directory entries before making activation
    # durable. This prevents a durable pointer to merely cached bundle files.
    for child in path.rglob('*'):
        if child.is_file():
            # Linux refuses write opens while an executable is mapped (ETXTBSY).
            # No writes remain here; fsync only needs a readable descriptor.
            with child.open('rb' if os.name != 'nt' else 'r+b') as stream:
                os.fsync(stream.fileno())
    for directory in sorted((p for p in path.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        sync_directory(directory)
    sync_directory(path)


def atomic_json(path, data):
    fd, name = tempfile.mkstemp(prefix='.state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            json.dump(data, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        sync_directory(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


class Deployment:
    def __init__(self, root):
        self.root = Path(os.path.abspath(root))
        private_dir(self.root)
        self.releases, self.config = self.root / 'releases', self.root / 'config'
        for directory in (self.releases, self.config):
            private_dir(directory)
        self.state_path = self.root / 'state.json'

    @contextmanager
    def lock(self):
        path = self.root / '.lock'
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError('invalid deployment lock')
            if os.fstat(fd).st_size == 0:
                os.write(fd, b'0')
            os.lseek(fd, 0, os.SEEK_SET)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)  # Kernel releases lock even after process death.

    def state(self):
        if not self.state_path.exists() and not self.state_path.is_symlink():
            return {'schema': 1, 'active': None, 'previous': None}
        regular(self.state_path)
        state = contract.read_json(self.state_path)
        if set(state) != {'schema', 'active', 'previous'} or type(state['schema']) is not int or state['schema'] != 1:
            raise ValueError('invalid deployment state; use explicit recover with a known release digest')
        for key in ('active', 'previous'):
            if state[key] is not None and (not isinstance(state[key], str) or not contract.HASH.fullmatch(state[key])):
                raise ValueError('invalid release pointer')
        return state

    def bundle(self, identity):
        if not isinstance(identity, str) or not contract.HASH.fullmatch(identity):
            raise ValueError('release identity must be a SHA-256 digest')
        path = self.releases / identity
        private_dir_existing(path)
        record_path = path / 'installation.json'
        if not record_path.exists():
            # A Necko manifest rejects untracked installation files. Its
            # deployment record lives beside (never inside) the bundle.
            record_path = self.releases / (identity + '.json')
        regular(record_path)
        record = contract.read_json(record_path)
        if type(record.get('schema')) is not int or record.get('schema') != 1 or record.get('identity') != identity or not isinstance(record.get('files'), dict):
            raise ValueError('invalid installed release record')
        if (record.get('goos'), record.get('goarch')) != target():
            raise ValueError('installed release is not native to this platform')
        seen = set()
        for child in path.rglob('*'):
            if child.is_symlink():
                raise ValueError('installed bundle contains a symlink')
            if child.is_dir():
                continue
            name = child.relative_to(path).as_posix()
            if name == 'installation.json':
                continue
            seen.add(name)
            if digest(child) != record['files'].get(name):
                raise ValueError('installed release was modified')
        if seen != set(record['files']):
            raise ValueError('installed release is incomplete')
        executable = 'vetroffproxy.exe' if target()[0] == 'windows' else 'vetroffproxy'
        if executable not in seen:
            raise ValueError('installed executable absent')
        return path / executable, record

    def install(self, source, expected_sha, version, commit, archive=False):
        contract.validate_version(version)
        if not contract.COMMIT.fullmatch(commit) or not contract.HASH.fullmatch(expected_sha):
            raise ValueError('provide a full source commit and trusted SHA-256')
        source = Path(source)
        regular(source)
        if not 0 < source.stat().st_size <= contract.MAX_TOTAL:
            raise ValueError('invalid source size')
        with self.lock(), tempfile.TemporaryDirectory(prefix='.stage-', dir=self.root) as stage:
            state = self.state()
            stage = Path(stage)
            # Work only on our private copy after this point, closing source
            # replacement races between verification, inspection and extraction.
            snapshot = stage / 'source'
            shutil.copyfile(source, snapshot)
            if digest(snapshot) != expected_sha:
                raise ValueError('source SHA-256 differs from the trusted value')
            package = stage / 'bundle'
            package.mkdir(mode=0o700)
            goos, arch = target()
            executable = 'vetroffproxy.exe' if goos == 'windows' else 'vetroffproxy'
            unified = archive and goos == 'linux' and arch in ('amd64', 'arm64') and source.name == (
                f'vetroffproxy_{version[1:]}_linux_{arch}.tar.gz')
            if unified:
                unified_archive.unpack(snapshot, package, version, commit, archive_name=source.name)
            elif archive:
                metadata = contract.embedded_metadata(snapshot)
                # embedded_metadata includes the snapshot filename. Restore the
                # reviewed release filename before validating the existing format.
                metadata['filename'] = source.name
                contract.validate_metadata(metadata, version, commit)
                if metadata['goos'] != goos or metadata['goarch'] != arch:
                    raise ValueError('archive is not for this native platform')
                contract.inspect_archive(snapshot, metadata)
                with tarfile.open(snapshot, 'r:gz') as tar:
                    for member in tar:
                        destination = package / member.name
                        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        with tar.extractfile(member) as input_file, destination.open('xb') as output:
                            shutil.copyfileobj(input_file, output)
                        destination.chmod(0o700 if member.name == executable else 0o600)
            else:
                shutil.copyfile(snapshot, package / executable)
                (package / executable).chmod(0o700)
            # Execute ONLY the exact locally supplied, hash-verified candidate,
            # before activation, with no inherited credentials/preload variables.
            env = {key: os.environ[key] for key in ('PATH', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE') if key in os.environ}
            info = contract.json_object(subprocess.check_output(
                [str(package / executable), 'version', '--json'], env=env, timeout=10))
            expected = {'schema': 1, 'version': version, 'commit': commit, 'goos': goos,
                        'goarch': arch, 'protocol_draft': contract.DRAFT, 'dirty': False}
            if not contract.same_json({key: info.get(key) for key in expected}, expected):
                raise ValueError('candidate build identity differs from reviewed version/commit/platform')
            if info.get('build_flavor') != ('nss' if archive else 'go'):
                raise ValueError('raw binaries must be Go-only; NSS requires its complete release archive')
            files = {p.relative_to(package).as_posix(): digest(p) for p in package.rglob('*') if p.is_file()}
            record = {'schema': 1, 'identity': expected_sha, 'version': version, 'commit': commit,
                      'goos': goos, 'goarch': arch, 'build_flavor': info['build_flavor'], 'files': files}
            if not unified:
                atomic_json(package / 'installation.json', record)
            sync_bundle(package)
            destination = self.releases / expected_sha
            if destination.exists() or destination.is_symlink():
                _, old_record = self.bundle(expected_sha)
                if old_record != record:
                    raise ValueError('existing release differs; refusing to overwrite')
            else:
                os.rename(package, destination)
                sync_directory(self.releases)
            if unified:
                atomic_json(self.releases / (expected_sha + '.json'), record)
            if state['active'] != expected_sha:
                atomic_json(self.state_path, {'schema': 1, 'active': expected_sha, 'previous': state['active']})
            return record

    def rollback(self):
        with self.lock():
            state = self.state()
            if not state['previous']:
                raise ValueError('no previous release')
            _, record = self.bundle(state['previous'])
            atomic_json(self.state_path, {'schema': 1, 'active': state['previous'], 'previous': state['active']})
            return record

    def recover(self, identity):
        with self.lock():
            _, record = self.bundle(identity)
            # Explicit operator action can replace corrupt activation state.
            atomic_json(self.state_path, {'schema': 1, 'active': identity, 'previous': None})
            return record


def private_dir_existing(path):
    if not path.exists() or path.is_symlink() or not path.is_dir():
        raise ValueError('installed release directory absent or unsafe')
    private_dir(path)


def launch(executable, forward):
    command = [str(executable), *forward]
    if sys.platform == 'win32':
        # Windows execv uses CRT overlay semantics: it does not preserve the
        # POSIX waitable process identity. Keep the launcher alive until its
        # child has exited, including release of the executable image mapping.
        return subprocess.call(command)
    os.execv(command[0], command)
    return 0  # Only reached by test doubles; successful POSIX exec never returns.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path, help='private per-user deployment directory')
    commands = parser.add_subparsers(dest='action', required=True)
    install = commands.add_parser('install')
    source = install.add_mutually_exclusive_group(required=True)
    source.add_argument('--binary', type=Path)
    source.add_argument('--archive', type=Path)
    install.add_argument('--sha256', required=True)
    install.add_argument('--version', required=True)
    install.add_argument('--commit', required=True)
    commands.add_parser('rollback')
    recover = commands.add_parser('recover')
    recover.add_argument('--release', required=True)
    commands.add_parser('status')
    run = commands.add_parser('run')
    run.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        deployment = Deployment(args.root)
        if args.action == 'install':
            record = deployment.install(args.archive or args.binary, args.sha256, args.version, args.commit, bool(args.archive))
        elif args.action == 'rollback':
            record = deployment.rollback()
        elif args.action == 'recover':
            record = deployment.recover(args.release)
        elif args.action == 'status':
            print(json.dumps(deployment.state(), sort_keys=True))
            return 0
        else:
            state = deployment.state()
            executable, _ = deployment.bundle(state['active'])
            forward = args.args[1:] if args.args[:1] == ['--'] else args.args
            if not forward:
                raise ValueError('provide VetroffProxy arguments after --')
            return launch(executable, forward)
        print(json.dumps({key: record[key] for key in ('identity', 'version', 'commit', 'goos', 'goarch', 'build_flavor')}, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError):
        print('Deployment refused or failed; inspect local inputs and activation state before retrying. Configuration files are never rewritten.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
