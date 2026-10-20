"""Recovery-budget regressions without real process or socket timeouts."""
import unittest
from unittest.mock import patch

import operations_soak as soak


class RecoveryBudget(unittest.TestCase):
    def run_recovery(self, schedule, budget):
        clock = [0.0]
        calls = []

        def advance(seconds):
            clock[0] += seconds

        def trial(name):
            calls.append(name)
            expected, duration, ok = schedule.pop(0)
            self.assertEqual(name, expected)
            advance(duration)
            return {'ok': ok}

        with patch.object(soak.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(soak.time, 'sleep', side_effect=advance):
            result = soak.recover_clients(('h2', 'h3'), trial, budget)
        return result, calls

    def test_retries_only_unrecovered_carrier(self):
        (recovered, elapsed, passed), calls = self.run_recovery([
            ('h2', .1, True), ('h3', .1, False), ('h3', .1, True)], 1)
        self.assertEqual(calls, ['h2', 'h3', 'h3'])
        self.assertEqual(recovered, {'h2': True, 'h3': True})
        self.assertAlmostEqual(elapsed, .4)
        self.assertTrue(passed)

    def test_success_after_deadline_does_not_pass(self):
        (recovered, elapsed, passed), _ = self.run_recovery([
            ('h2', .1, True), ('h3', 30, True)], 30)
        self.assertTrue(all(recovered.values()))
        self.assertGreater(elapsed, 30)
        self.assertFalse(passed)

    def test_does_not_start_another_trial_after_budget_expires(self):
        (recovered, elapsed, passed), calls = self.run_recovery([
            ('h2', 30, False)], 30)
        self.assertEqual(calls, ['h2'])
        self.assertFalse(any(recovered.values()))
        self.assertGreaterEqual(elapsed, 30)
        self.assertFalse(passed)

    def test_last_success_uses_remaining_budget_without_extra_sleep(self):
        (_, elapsed, passed), _ = self.run_recovery([
            ('h2', .1, True), ('h3', 29.85, True)], 30)
        self.assertAlmostEqual(elapsed, 29.95)
        self.assertTrue(passed)


if __name__ == '__main__':
    unittest.main()
