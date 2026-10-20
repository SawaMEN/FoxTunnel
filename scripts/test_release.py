import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import release
import release_verify as verify


class ReleaseContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = argparse.Namespace(input=str(self.root), version='v0.1.0-alpha.1', targets=None)
        self.entries = []
        for target in sorted(release.TARGETS):
            goos, arch, flavor = target.split('/')
            suffix = '.tar.gz'
            name = 'foxtunnel_0.1.0-alpha.1_' + target.replace('/', '_') + suffix
            runtime = dict(kind='cgo-disabled')
            if flavor == 'nss':
                provenance = dict(schema=1, firefox_version='158.0', nss_version='3.130',
                                  archive_url='https://archive.mozilla.org/pub/firefox/releases/158.0/firefox.tar.xz',
                                  archive_sha256='c' * 64,
                                  source_url='https://archive.mozilla.org/pub/firefox/releases/158.0/source.tar.xz',
                                  source_sha256='d' * 64,
                                  libraries={'libnss3.so': hashlib.sha256(b'library').hexdigest()})
                runtime = dict(kind='bundled-nss', baseline='ubuntu-24.04', packages=['glibc', 'libgcc-s1'],
                               nss_version='3.130', mozilla=provenance)
            p = dict(schema=1, product='protocol-core', integration_schema=1, version=self.args.version, commit='a' * 40, dirty=False,
                     experimental=True, build_date='2026-10-18T19:00:00Z', target=target,
                     goos=goos, goarch=arch,
                     variant='', build_flavor=flavor,
                     tls_backends=['go', 'nss'] if flavor == 'nss' else ['go'], default_tls_backend='nss',
                     protocol_draft=verify.DRAFT, native_smoke_tested=True, runtime=runtime,
                     filename=name)
            meta = self.root / (name + '.metadata.json')
            meta.write_text(json.dumps(p))
            self.entries.append(meta)
            self.pack(len(self.entries) - 1)
        self.verify_args = argparse.Namespace(input=str(self.root), version=self.args.version,
                                              commit='a' * 40, target=None)

    def pack(self, index, mutate=None, extra=()):
        path = self.entries[index]
        p = json.loads(path.read_text())
        build = {k: v for k, v in p.items() if k not in verify.ARCHIVE_FIELDS}
        files = {'build.json': json.dumps(build).encode(), 'LICENSE': b'MIT',
                 'THIRD_PARTY_NOTICES.txt': b'notices', 'licenses/Go-LICENSE': b'BSD',
                 'foxtunnel': b'fixture executable, never run'}
        files.update(release.integration_files())
        if p['build_flavor'] == 'nss':
            files.update({'mozilla-runtime.json': json.dumps(p['runtime']['mozilla']).encode(),
                          'licenses/Mozilla-about-license.html': b'Mozilla notices', 'lib/libnss3.so': b'library'})
        if mutate:
            mutate(files)
        archive = self.root / p['filename']
        with tarfile.open(archive, 'w:gz') as tar:
            for name, data in files.items():
                item = tarfile.TarInfo(name)
                item.mode, item.size = 0o755, len(data)
                tar.addfile(item, io.BytesIO(data))
            for item, data in extra:
                tar.addfile(item, io.BytesIO(data))
        p.update(sha256=release.sha(archive), size=archive.stat().st_size)
        path.write_text(json.dumps(p))

    def find(self, target):
        return next(i for i, p in enumerate(self.entries) if json.loads(p.read_text())['target'] == target)

    def edit(self, key, value, index=0):
        path = self.entries[index]
        p = json.loads(path.read_text())
        p[key] = value
        path.write_text(json.dumps(p))

    def expect_index_error(self, expression=None):
        with self.assertRaisesRegex(ValueError, expression or '.'):
            release.index(self.args)
        self.assertFalse((self.root / 'manifest.json').exists())
        self.assertFalse((self.root / 'SHA256SUMS').exists())

    def test_complete_index_and_offline_verification_without_sidecars(self):
        release.index(self.args)
        self.assertFalse((self.root / 'manifest.json').exists())
        self.assertFalse((self.root / 'SHA256SUMS').exists())
        for path in self.entries:
            path.unlink()
        verify.verify(self.verify_args)

    def test_selected_archive_only_and_full_release_checks(self):
        release.index(self.args)
        self.verify_args.target = 'linux/arm64/nss'
        selected = json.loads(self.entries[self.find(self.verify_args.target)].read_text())['filename']
        for p in self.root.glob('foxtunnel_*'):
            if p.name != selected:
                p.unlink()
        verify.verify(self.verify_args)
        self.verify_args.target = None
        with self.assertRaises(ValueError):
            verify.verify(self.verify_args)

    def test_integration_contract_required_and_exact(self):
        self.pack(0, lambda files: files.pop('integration.json'))
        self.expect_index_error('required archive member')
        self.pack(0, lambda files: files.update({'integration.json': b'{}'}))
        self.expect_index_error('integration contract mismatch')
        self.pack(0, lambda files: files.update({'install-vpn.sh': b'#!/bin/sh'}))
        self.expect_index_error('unexpected archive member')

    def test_corruption_rejected(self):
        p = json.loads(self.entries[0].read_text())
        (self.root / p['filename']).write_bytes(b'tampered')
        self.expect_index_error('hash/size')

    def test_incomplete_rejected(self):
        self.entries[0].unlink()
        self.expect_index_error('target set')

    def test_dirty_rejected(self):
        self.edit('dirty', True)
        self.expect_index_error('clean')

    def test_mixed_commit_rejected(self):
        self.edit('commit', 'b' * 40, index=1)
        self.expect_index_error('commit')

    def test_path_escape_rejected(self):
        self.edit('filename', '../outside')
        self.expect_index_error('filename')

    def test_unknown_target_rejected(self):
        self.args.targets = 'plan9/amd64/go'
        self.expect_index_error('target set')

    def test_bad_metadata_types_and_contract_rejected(self):
        original = json.loads(self.entries[0].read_text())
        for key, value in [('schema', True), ('dirty', 0), ('experimental', 1), ('size', True),
                           ('native_smoke_tested', 1), ('sha256', 'no'), ('goarch', 'wrong'),
                           ('tls_backends', ['nss']), ('protocol_draft', 'future'),
                           ('commit', 'short'), ('build_date', '2026-02-30T00:00:00Z'),
                           ('default_tls_backend', 'go'), ('runtime', {'kind': 'system-nss'})]:
            with self.subTest(key=key):
                self.entries[0].write_text(json.dumps(original))
                self.edit(key, value)
                self.expect_index_error()

    def test_embedded_metadata_mismatch_with_correct_outer_hash_rejected(self):
        def change(files):
            build = json.loads(files['build.json'])
            build['commit'] = 'b' * 40
            files['build.json'] = json.dumps(build).encode()
        self.pack(0, change)
        self.expect_index_error('embedded build.json')

    def test_embedded_boolean_cannot_alias_integer(self):
        def change(files):
            build = json.loads(files['build.json'])
            build['dirty'] = 0
            files['build.json'] = json.dumps(build).encode()
        self.pack(0, change)
        self.expect_index_error('embedded build.json')

    def test_missing_binary_rejected(self):
        self.pack(0, lambda files: files.pop('foxtunnel'))
        self.expect_index_error('required archive member')

    def test_changed_library_and_provenance_rejected(self):
        index = self.find('linux/amd64/nss')
        self.pack(index, lambda files: files.update({'lib/libnss3.so': b'tampered library'}))
        self.expect_index_error('library hash')
        self.pack(index, lambda files: files.update({'mozilla-runtime.json': b'{}'}))
        self.expect_index_error('provenance')
        self.pack(index, lambda files: files.pop('licenses/Mozilla-about-license.html'))
        self.expect_index_error('Mozilla license')

    def test_unsafe_tar_names_rejected(self):
        for target in ('linux/amd64/nss',):
            index = self.find(target)
            for name in ('../outside', '/outside', 'licenses/../outside', 'licenses\\outside',
                         'C:outside', 'CON', 'licenses/Go-LICENSE.'):
                with self.subTest(target=target, name=name):
                    self.pack(index, lambda files: files.update({name: b'bad'}))
                    self.expect_index_error('unsafe')
            self.pack(index)

    def test_tar_links_special_files_duplicates_and_modes_rejected(self):
        index = self.find('linux/amd64/nss')
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind):
                item = tarfile.TarInfo('licenses/link')
                item.type, item.linkname = kind, '../../outside'
                self.pack(index, extra=[(item, b'')])
                self.expect_index_error('link/special')
        item = tarfile.TarInfo('LICENSE')
        item.size = 3
        self.pack(index, extra=[(item, b'dup')])
        self.expect_index_error('duplicate')
        item = tarfile.TarInfo('licenses/privileged')
        item.size, item.mode = 3, 0o4755
        self.pack(index, extra=[(item, b'bad')])
        self.expect_index_error('privileged')

    def test_limits_enforced(self):
        # Small limits exercise the same streaming guards without allocating a bomb.
        with patch.object(verify, 'MAX_MEMBER', 16):
            self.expect_index_error('release limit')
        with patch.object(verify, 'MAX_TOTAL', 10000), patch.object(verify, 'MAX_MEMBERS', 2):
            self.expect_index_error('excess')
        with patch.object(verify, 'MAX_TOTAL', 600):
            self.expect_index_error('size|release limit')
        with patch.object(verify, 'MAX_JSON', 32):
            self.expect_index_error('JSON')

    def test_invalid_embedded_json_rejected(self):
        for data in (b'{"schema":1,"schema":2}', b'{"schema":NaN}', b'[]'):
            with self.subTest(data=data):
                self.pack(0, lambda files: files.update({'build.json': data}))
                self.expect_index_error()

    def test_trusted_source_commit_and_version_required(self):
        release.index(self.args)
        for version, commit in [('v9.0.0', 'a' * 40),
                                (self.args.version, 'b' * 40)]:
            self.verify_args.version, self.verify_args.commit = version, commit
            with self.assertRaisesRegex(ValueError, 'no release archives|mismatch'):
                verify.verify(self.verify_args)
        self.verify_args.version, self.verify_args.commit = self.args.version, 'a' * 40

    def test_no_checksum_or_manifest_outputs(self):
        release.index(self.args)
        self.assertFalse((self.root / 'manifest.json').exists())
        self.assertFalse((self.root / 'SHA256SUMS').exists())
        for path in self.entries:
            path.unlink()
        verify.verify(self.verify_args)

    def test_only_supported_linux_targets(self):
        self.assertEqual({'linux/amd64/nss', 'linux/arm64/nss'}, verify.TARGETS)
        self.verify_args.target = 'windows/amd64/go'
        with self.assertRaisesRegex(ValueError, 'unsupported requested target'):
            verify.verify(self.verify_args)

    def test_version_contract(self):
        for good in ['v0.1.0-alpha.1', 'v1.2.3', 'v1.2.3-rc-1']:
            release.validate_version(good)
        for bad in ['1.2.3', 'v01.0.0', 'v1.2.3-..', 'v1.2.3-01', 'v1.2.3/other']:
            with self.assertRaises(ValueError):
                release.validate_version(bad)


if __name__ == '__main__':
    unittest.main()
