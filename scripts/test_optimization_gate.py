import unittest

import optimization_gate as gate


class OptimizationGate(unittest.TestCase):
    def samples(self):
        return [dict(variant=variant, repeat=i, cases={case: dict(ns=100., bytes=64, allocations=1)
                     for case in gate.CASES}) for variant in ('base', 'head') for i in range(gate.REPEATS)]

    def test_rejects_incomplete_duplicate_and_failed_measurements(self):
        for mutate in (lambda s: s.pop(), lambda s: s[-1].update(repeat=0),
                       lambda s: s[-1]['cases'].pop(next(iter(gate.CASES))),
                       lambda s: s[-1]['cases'][next(iter(gate.CASES))].update(ns=float('nan'))):
            samples = self.samples()
            mutate(samples)
            with self.assertRaises(ValueError):
                gate.compare(samples)
        with self.assertRaises(ValueError):
            gate.parse('PASS\n')
        with self.assertRaises(ValueError):
            gate.parse('FAIL\n')

    def test_rejects_timing_allocation_and_noise_regressions(self):
        for metric, value in (('ns', 126.), ('bytes', 65), ('allocations', 2)):
            samples = self.samples()
            for sample in samples[gate.REPEATS:]:
                for metrics in sample['cases'].values():
                    metrics[metric] = value
            self.assertTrue(all(not r['passed'] for r in gate.compare(samples)))
        samples = self.samples()
        for i, sample in enumerate(samples[gate.REPEATS:]):
            for metrics in sample['cases'].values():
                metrics['ns'] = 40. if i < 3 else (160. if i > 3 else 100.)
        self.assertTrue(all(not r['stable'] and not r['passed'] for r in gate.compare(samples)))

    def test_allows_improvement_and_exact_boundary(self):
        samples = self.samples()
        self.assertTrue(all(r['passed'] for r in gate.compare(samples)))
        for sample in samples[gate.REPEATS:]:
            for metrics in sample['cases'].values():
                metrics.update(ns=125., bytes=0, allocations=0)
        self.assertTrue(all(r['passed'] for r in gate.compare(samples)))

    def test_parser_requires_each_case_once(self):
        lines = [f'{case}-1 10000 100.5 ns/op 64 B/op 1 allocs/op' for case in sorted(gate.CASES)]
        self.assertEqual(set(gate.parse('\n'.join(lines + ['PASS']))), gate.CASES)
        with self.assertRaises(ValueError):
            gate.parse('\n'.join(lines + [lines[0], 'PASS']))

        with self.assertRaises(ValueError):
            gate.parse('\n'.join(lines + ['BenchmarkStage10Selector/2/fresh invalid', 'PASS']))
