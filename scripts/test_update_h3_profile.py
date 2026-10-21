import copy
import unittest

import update_h3_profile as profile


class H3Profile(unittest.TestCase):
    def samples(self):
        return [dict(variant=v, scenario=s, repeat=r,
                     **{key: 100 + r for key in profile.KEYS})
                for v in profile.VARIANTS for s in profile.metrics.SCENARIOS
                for r in range(profile.REPEATS)]

    def test_paired_summary_and_dispersion(self):
        rows = profile.summarize(self.samples())
        self.assertEqual(len(rows), 4)
        self.assertTrue(all(r['stable'] for r in rows))
        stats = rows[0]['metrics']['ns_per_exchange']
        self.assertEqual(stats['median'], 103)
        self.assertEqual(stats['minimum'], 100)
        self.assertEqual(stats['maximum'], 106)
        self.assertAlmostEqual(stats['relative_mad'], 2 / 103)

    def test_reject_incomplete_duplicate_and_invalid_evidence(self):
        samples = self.samples()
        duplicate = copy.deepcopy(samples)
        duplicate[-1] = duplicate[0]
        for rows in (samples[:-1], samples + samples[:1], duplicate):
            with self.assertRaises(ValueError):
                profile.summarize(rows)
        for value in (-1, float('nan'), float('inf'), '123', True):
            rows = self.samples()
            rows[0]['process_peak_rss_kib'] = value
            with self.assertRaises(ValueError):
                profile.summarize(rows)

    def test_unstable_sample_is_reported_without_speed_claim(self):
        rows = self.samples()
        for row in rows:
            row['ns_per_exchange'] = 10 ** row['repeat']
        self.assertTrue(all(not r['stable'] for r in profile.summarize(rows)))


if __name__ == '__main__':
    unittest.main()
