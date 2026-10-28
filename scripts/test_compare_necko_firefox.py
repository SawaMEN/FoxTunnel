import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import compare_necko_firefox as audit


def observation(mode):
    hello = dict(legacy_version=771, cipher_suites=[4865], extensions=[10, 16],
                 supported_groups=[29], ec_point_formats=[])
    hello['ja3'] = audit.ja3_expected(hello)
    hello['ja3_md5'] = hashlib.md5(hello['ja3'].encode('ascii')).hexdigest()
    connection = dict(hello=hello, settings=[dict(id=1, value=1)], requests=2,
                      completed=2, alpn=mode[:2], client_fin_streams=[0, 4],
                      resumed=False, client_reset_codes=[])
    connections = []
    for subject in ('firefox', 'foxtunnel'):
        for _ in range(2):
            c = copy.deepcopy(connection)
            c['subject'] = subject
            connections.append(c)
    return dict(schema=1, kind='necko-firefox-connect-comparison', transport=mode,
                connections=connections, runtime_sha256={'libxul.so': 'a' * 64},
                source_sha256={'client.js': 'b' * 64})


class ComparisonTests(unittest.TestCase):
    def test_missing_protocol_and_mixed_binaries_never_pass(self):
        with tempfile.TemporaryDirectory() as root:
            a, b = Path(root) / 'a.json', Path(root) / 'b.json'
            data = observation('h2-connect')
            a.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                audit.report([a])
            data = observation('h3-connect')
            b.write_text(json.dumps(data))
            self.assertTrue(audit.report([a, b])['both_protocols_measured'])
            with self.assertRaises(ValueError):
                audit.report([a, b], minimum=3)
            data['runtime_sha256']['libxul.so'] = 'c' * 64
            b.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                audit.report([a, b])

    def test_missing_eof_and_truncation_are_rejected(self):
        for change in ({'truncated': True}, {'completed': 1}, {'hello': None},
                       {'client_fin_streams': [0]}, {'error': 'decode failed'}):
            with tempfile.TemporaryDirectory() as root:
                data = observation('h2-connect')
                data['connections'][0].update(change)
                path = Path(root) / 'a.json'
                path.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    audit.read(path)

    def test_order_difference_remains_visible_with_equal_sets(self):
        data = observation('h3-connect')
        a, b = data['connections'][:2], data['connections'][2:]
        b[0]['hello']['extensions'].reverse()
        rows = {row['field']: row for row in audit.checks(a, b)}
        self.assertEqual(rows['connection_1.hello.extensions']['status'], 'different')
        self.assertEqual(rows['connection_1.hello.extension_set']['status'], 'equal')


if __name__ == '__main__':
    unittest.main()
