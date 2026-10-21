import unittest

import native_backend_metrics as metrics


class NativeBackendMetrics(unittest.TestCase):
    def sample(self, variant='neqo-h3', scenario='bulk'):
        name = metrics.VARIANTS[variant] + '/' + metrics.SCENARIOS[scenario][0]
        count = metrics.SCENARIOS[scenario][2]
        return f'{name}-2 {count} 4000000 ns/op 262.14 MB/s 1200 B/op 20 allocs/op\nPASS\n'

    def test_exact_case_and_iteration_required(self):
        result = metrics.parse_result(self.sample(), 'neqo-h3', 'bulk')
        self.assertEqual(result['iterations'], 16)
        self.assertEqual(result['bytes_per_exchange'], 1 << 20)
        for log in (self.sample().replace(' 16 ', ' 15 '), self.sample().replace('PASS', 'FAIL'),
                    self.sample() + self.sample(), self.sample('go-h3')):
            with self.subTest(log=log):
                with self.assertRaises(ValueError):
                    metrics.parse_result(log, 'neqo-h3', 'bulk')

    def test_invalid_timing_and_missing_case_rejected(self):
        for log in ('PASS\n', self.sample().replace('4000000', '0'),
                    self.sample().replace('262.14', '0'), self.sample().replace('4000000', 'NaN')):
            with self.assertRaises(ValueError):
                metrics.parse_result(log, 'neqo-h3', 'bulk')


if __name__ == '__main__':
    unittest.main()
