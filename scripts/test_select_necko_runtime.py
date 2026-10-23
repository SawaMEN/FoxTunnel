import unittest
from select_necko_runtime import matching_run


class SelectorTests(unittest.TestCase):
    def test_never_uses_older_lock_while_source_build_is_running(self):
        runs = [dict(id=2, head_sha='new', status='in_progress'),
                dict(id=1, head_sha='old', status='completed')]
        sources = {'new': {'revision': 2}, 'old': {'revision': 1}}
        artifacts = {1: [dict(name='necko-linux-amd64-runtime'), dict(name='necko-source-provenance')], 2: []}
        self.assertEqual(matching_run(runs, {'revision': 2}, sources.get, artifacts.get), (None, True))
        artifacts[2] = artifacts[1]
        self.assertEqual(matching_run(runs, {'revision': 2}, sources.get, artifacts.get)[0], 2)

    def test_missing_or_expired_artifacts_do_not_count(self):
        runs = [dict(id=2, head_sha='new', status='completed')]
        for artifacts in ([], [dict(name='necko-linux-amd64-runtime', expired=True),
                              dict(name='necko-source-provenance')]):
            self.assertEqual(matching_run(runs, {}, lambda _: {}, lambda _: artifacts), (None, False))


if __name__ == '__main__':
    unittest.main()
