import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import evidence_bundle as evidence


class EvidenceContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry = json.loads((evidence.ROOT / evidence.MANIFEST).read_text())
        for entry in self.registry['observations']:
            dest = self.root / entry['path']
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(evidence.ROOT / entry['path'], dest)
        self.save()

    def save(self):
        path = self.root / evidence.MANIFEST
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.registry))

    def edit_operations(self, change):
        entry = next(e for e in self.registry['observations'] if e['kind'] == 'native_operations')
        path = self.root / entry['path']
        raw = json.loads(path.read_text())
        change(raw)
        data = json.dumps(raw).encode()
        path.write_bytes(data)
        entry['sha256'] = hashlib.sha256(data).hexdigest()
        self.save()

    def test_reviewed_captures_do_not_imply_equivalence_or_audit(self):
        result = evidence.validate(self.root)
        self.assertTrue(result['integrity_checks_passed'])
        self.assertTrue(result['all_six_captures_present'])
        self.assertTrue(all(v == 'observed' for v in result['coverage'].values()))
        self.assertEqual(result['independent_security_audit'], 'not_provided')
        comparison = result['comparisons_to_firefox']['vetroff']
        self.assertGreater(comparison['tls']['counts']['different'], 0)
        self.assertFalse(comparison['metadata_equal'])

    def test_missing_captures_remain_unmeasured(self):
        self.registry['comparison']['naive_tls_h2'] = None
        self.registry['comparison']['vetroff_quic_h3'] = None
        self.save()
        result = evidence.validate(self.root)
        self.assertFalse(result['all_six_captures_present'])
        self.assertEqual(result['coverage']['naive_tls_h2'], 'not_measured')
        self.assertEqual(result['coverage']['vetroff_quic_h3'], 'not_measured')

    def test_modified_capture_requires_reviewed_hash(self):
        path = self.root / self.registry['observations'][0]['path']
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            evidence.validate(self.root)

    def test_registry_keeps_strict_ja3_validation_after_hash_review(self):
        entry = self.registry['observations'][0]
        path = self.root / entry['path']
        raw = json.loads(path.read_text())
        raw['hello']['ja3'] = 'forged'
        data = json.dumps(raw).encode()
        path.write_bytes(data)
        entry['sha256'] = hashlib.sha256(data).hexdigest()
        self.save()
        with self.assertRaisesRegex(ValueError, 'JA3'):
            evidence.validate(self.root)

    def test_quic_registry_kind_maps_to_strict_capture_decoder(self):
        raw = {'schema': 1, 'kind': 'h3-quic-observation', 'capture_method': 'endpoint',
               'capture_scenario': 'synthetic unit fixture, not a measured profile',
               'quic': {'version': 1, 'tls_alpn': 'h3', 'initial_datagram_size': 1200,
                        'transport_parameters': [{'id': 1, 'value': 2000}]},
               'h3': {'settings': [{'id': 6, 'value': 1024}]}}
        data = json.dumps(raw).encode()
        name = 'docs/measurements/unit-quic.json'
        (self.root / name).write_bytes(data)
        self.registry['observations'].append(dict(id='unit-quic', path=name, sha256=hashlib.sha256(data).hexdigest(),
                                                 kind='quic_h3', subject='vetroff', scope='controlled-loopback', source_commit=None))
        self.registry['comparison']['vetroff_quic_h3'] = 'unit-quic'
        self.registry['comparison']['naive_quic_h3'] = None
        self.save()
        result = evidence.validate(self.root)
        self.assertEqual(result['coverage']['vetroff_quic_h3'], 'observed')
        self.assertFalse(result['all_six_captures_present'])
        raw['quic']['transport_parameters'].append({'id': 1, 'value': 5000})
        data = json.dumps(raw).encode()
        (self.root / name).write_bytes(data)
        self.registry['observations'][-1]['sha256'] = hashlib.sha256(data).hexdigest()
        self.save()
        with self.assertRaisesRegex(ValueError, 'decoded QUIC/H3'):
            evidence.validate(self.root)

    def test_incomplete_native_matrix_not_promoted_to_pass(self):
        self.edit_operations(lambda raw: raw['results'].pop())
        with self.assertRaisesRegex(ValueError, 'matrix'):
            evidence.validate(self.root)

    def test_pass_marker_cannot_hide_late_recovery(self):
        self.edit_operations(lambda raw: raw['results'][0]['summary'].update(recovery_seconds=30.01))
        with self.assertRaisesRegex(ValueError, 'recovery budget'):
            evidence.validate(self.root)

    def test_input_cannot_relax_reviewed_budgets(self):
        self.edit_operations(lambda raw: raw['settings'].update(recovery_budget_seconds=120))
        with self.assertRaisesRegex(ValueError, 'unreviewed'):
            evidence.validate(self.root)

    def test_low_success_rate_cannot_hide_behind_pass_marker(self):
        self.edit_operations(lambda raw: raw['results'][0]['summary']['load']['h3'].update(succeeded=0))
        with self.assertRaisesRegex(ValueError, 'load threshold'):
            evidence.validate(self.root)

    def test_missing_handles_not_treated_as_zero(self):
        def change(raw):
            row = next(r for r in raw['results'] if r['runner'] == 'windows-latest')
            del row['summary']['resources']['server']['peak']['handle_count']
        self.edit_operations(change)
        with self.assertRaisesRegex(ValueError, 'descriptor'):
            evidence.validate(self.root)

    def test_source_commit_mismatch_rejected(self):
        self.edit_operations(lambda raw: raw['workflow'].update(head_sha='f' * 40))
        with self.assertRaisesRegex(ValueError, 'source mismatch'):
            evidence.validate(self.root)

    def test_reported_growth_cannot_hide_actual_growth(self):
        def change(raw):
            resource = raw['results'][0]['summary']['resources']['server']
            resource['last_rss_kib'] = resource['initial_rss_kib'] + 200 * 1024
            resource['peak']['rss_kib'] = resource['last_rss_kib']
            resource['growth_kib'] = 0
        self.edit_operations(change)
        with self.assertRaisesRegex(ValueError, 'memory budget'):
            evidence.validate(self.root)

    def test_cross_compilation_is_not_native_execution(self):
        self.edit_operations(lambda raw: raw['results'][0]['build'].update(goos='linux'))
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            evidence.validate(self.root)

    def test_missing_quic_cannot_be_replaced_with_h2(self):
        self.registry['comparison']['vetroff_quic_h3'] = 'vetroff-nss-h2'
        self.save()
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            evidence.validate(self.root)

    def test_duplicate_json_keys_unknown_fields_and_boolean_schema_rejected(self):
        path = self.root / evidence.MANIFEST
        original = path.read_text()
        path.write_text(original.replace('"schema": 1', '"schema": 1, "schema": 1', 1))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            evidence.validate(self.root)
        self.registry['schema'] = True
        self.save()
        with self.assertRaises(ValueError):
            evidence.validate(self.root)
        self.registry['schema'] = 1
        self.registry['observations'][0]['password'] = 'must-not-be-exported'
        self.save()
        with self.assertRaisesRegex(ValueError, 'fields'):
            evidence.validate(self.root)

    def test_path_traversal_and_absolute_paths_rejected(self):
        for path in ('docs/measurements/../../go.mod', '/etc/passwd', 'docs/measurements/./file',
                     'docs/measurements/..\\secret', 'docs/measurements//file'):
            with self.subTest(path=path):
                self.registry['observations'][0]['path'] = path
                self.save()
                with self.assertRaises(ValueError):
                    evidence.validate(self.root)

    def test_symlink_parent_rejected(self):
        docs = self.root / 'docs'
        moved = self.root / 'relocated'
        docs.rename(moved)
        try:
            docs.symlink_to(moved, target_is_directory=True)
        except OSError:
            self.skipTest('platform disallows creating symlinks')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            evidence.validate(self.root)

    def test_oversized_and_nonfinite_input_rejected(self):
        path = self.root / self.registry['observations'][0]['path']
        path.write_bytes(b' ' * (evidence.MAX_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'size limit'):
            evidence.validate(self.root)
        with self.assertRaises(ValueError):
            evidence.decode(b'{"schema":NaN}')

    def test_audit_handoff_identity_inventory_and_exclusive_output(self):
        output = self.root / 'handoff.json'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(evidence.main(['--out', str(output)]), 0)
        report = json.loads(output.read_text())
        self.assertRegex(report['checkout_commit'], '^[0-9a-f]{40}$')
        self.assertIs(type(report['worktree_dirty']), bool)
        self.assertEqual({r['path'] for r in report['dependency_inputs']}, set(evidence.LOCKS))
        self.assertNotIn(str(evidence.ROOT), output.read_text())
        before = output.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(evidence.main(['--out', str(output)]), 2)
        self.assertEqual(output.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
