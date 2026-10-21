import json
import unittest

import sdk_evidence as sdk


class SDKExecutionEvidence(unittest.TestCase):
    def events(self):
        rows = []
        for name in sorted(sdk.EXPECTED):
            rows.extend([dict(Action='run', Test=name, Package=sdk.PACKAGE),
                         dict(Action='pass', Test=name, Package=sdk.PACKAGE)])
        rows.append(dict(Action='pass', Package=sdk.PACKAGE))
        return rows

    def encode(self, rows):
        return ('\n'.join(json.dumps(r) for r in rows) + '\n').encode()

    def test_requires_all_twenty_two_actually_executed_cases(self):
        report = sdk.summarize(self.encode(self.events()), 'a' * 40, 'linux')
        self.assertTrue(report['passed'])
        self.assertEqual(report['required_case_count'], 22)
        self.assertEqual(set(report['executed_required_cases']), sdk.EXPECTED)

    def test_skipped_or_missing_case_never_passes(self):
        for action in ('skip', 'output'):
            rows = self.events()
            rows[1]['Action'] = action
            with self.subTest(action=action), self.assertRaises(ValueError):
                sdk.summarize(self.encode(rows), 'a' * 40, 'linux')

    def test_failures_package_identity_and_order_matter(self):
        for update in (dict(Action='fail'), dict(Action='pass'), dict(Package='other/module')):
            rows = self.events()
            rows[0].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError):
                sdk.summarize(self.encode(rows), 'a' * 40, 'linux')

    def test_duplicate_run_and_absent_package_result_rejected(self):
        for rows in (self.events()[:-1], [self.events()[0]] + self.events()):
            with self.assertRaises(ValueError):
                sdk.summarize(self.encode(rows), 'a' * 40, 'linux')


if __name__ == '__main__':
    unittest.main()
