import unittest

import update_h3_compare as compare
import test_update_h3_profile as fixtures


class H3Compare(unittest.TestCase):
    def samples(self):
        return [dict(build=b, **s) for b in ('base', 'head') for s in fixtures.H3Profile().samples()]

    def test_separates_allocations_from_latency(self):
        samples = self.samples()
        for s in samples:
            if s['build'] == 'head' and s['variant'] == 'neqo-h3':
                s['go_allocations_per_exchange'] *= .5
        rows = compare.compare(samples)['comparisons']
        for row in rows:
            self.assertTrue(row['stable'])
            self.assertEqual(row['allocations_reduced'], row['variant'] == 'neqo-h3')
            self.assertFalse(row['latency_improved'])
            self.assertFalse(row['latency_regression'])
            self.assertEqual(row['paired_time_ratio_median'], 1)

    def test_rejects_missing_build_and_duplicate_pair(self):
        samples = self.samples()
        for rows in (samples[:-1], samples + samples[:1], samples[:-1] + samples[:1]):
            with self.assertRaises(ValueError):
                compare.compare(rows)


if __name__ == '__main__':
    unittest.main()
