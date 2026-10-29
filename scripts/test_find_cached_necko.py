"""Offline cache eligibility tests (no GitHub credentials required)."""
import unittest

from find_cached_necko import (BUILD_INPUTS, REQUIRED_ARTIFACTS, REQUIRED_NATIVE_JOBS,
                              matching_compiled_run, normalize_build_input)


class NativeCacheTests(unittest.TestCase):
    def setUp(self):
        self.expected = {name: (name + ':current').encode() for name in BUILD_INPUTS}
        self.runs = [dict(id=20, status='completed', conclusion='success',
                          head_branch='main', event='push', head_sha='candidate')]
        self.sources = {('candidate', name): content for name, content in self.expected.items()}
        self.artifacts = {20: [dict(name=name, size_in_bytes=123, expired=False)
                               for name in REQUIRED_ARTIFACTS]}

    def find(self):
        return matching_compiled_run(
            self.runs, self.expected,
            lambda sha, name: self.sources.get((sha, name)),
            lambda run_id: self.artifacts[run_id])

    def test_reuses_fully_matching_successful_main_build(self):
        self.assertEqual(self.find(), 20)

    def test_cannot_reuse_changed_gecko_patch_or_compiler_inputs(self):
        for name in BUILD_INPUTS:
            with self.subTest(name=name):
                old = self.sources[('candidate', name)]
                self.sources[('candidate', name)] = b'old input'
                self.assertIsNone(self.find())
                self.sources[('candidate', name)] = old

    def test_requires_both_architectures_and_unexpired_artifacts(self):
        for name in REQUIRED_ARTIFACTS:
            with self.subTest(name=name):
                a = next(x for x in self.artifacts[20] if x['name'] == name)
                self.artifacts[20].remove(a)
                self.assertIsNone(self.find())
                self.artifacts[20].append(a)
                a['expired'] = True
                self.assertIsNone(self.find())
                a['expired'] = False
                a['size_in_bytes'] = 0
                self.assertIsNone(self.find())
                a['size_in_bytes'] = 123

    def test_rejects_untrusted_or_incomplete_workflow(self):
        for field, bad in [('status', 'in_progress'), ('conclusion', 'cancelled'),
                           ('head_branch', 'feature'), ('event', 'pull_request')]:
            with self.subTest(field=field):
                old = self.runs[0][field]
                self.runs[0][field] = bad
                self.assertIsNone(self.find())
                self.runs[0][field] = old

    def test_skips_newer_incomplete_run_and_selects_older_valid_build(self):
        newer = dict(self.runs[0], id=30, head_sha='newer')
        self.runs.append(newer)
        self.artifacts[30] = [dict(name='necko-linux-amd64-runtime', size_in_bytes=25)]
        for name, value in self.expected.items():
            self.sources[('newer', name)] = value
        self.assertEqual(self.find(), 20)

    def test_failed_publish_reuses_verified_native_results(self):
        self.runs[0]['conclusion'] = 'failure'
        self.assertIsNone(self.find())  # No job evidence, fail closed.
        ok_jobs = [dict(name=name, conclusion='success') for name in REQUIRED_NATIVE_JOBS]
        result = matching_compiled_run(
            self.runs, self.expected,
            lambda sha, name: self.sources.get((sha, name)),
            lambda run_id: self.artifacts[run_id],
            lambda run_id: ok_jobs)
        self.assertEqual(result, 20)
        ok_jobs[0]['conclusion'] = 'failure'
        self.assertIsNone(matching_compiled_run(
            self.runs, self.expected,
            lambda sha, name: self.sources.get((sha, name)),
            lambda run_id: self.artifacts[run_id],
            lambda run_id: ok_jobs))

    def test_retention_change_does_not_invalidate_compiler(self):
        path = '.github/workflows/necko-experiment.yml'
        before = b'name: source\n          retention-days: 7\nrun: build\n'
        after = b'name: source\n          retention-days: 30\nrun: build\n'
        self.assertEqual(normalize_build_input(path, before),
                         normalize_build_input(path, after))
        self.assertNotEqual(normalize_build_input(path, before),
                            normalize_build_input(path, after.replace(b'run: build', b'run: other')))

    def test_absent_source_or_architecture_falls_back_to_compilation(self):
        self.sources.pop(('candidate', BUILD_INPUTS[0]))
        self.assertIsNone(self.find())
        self.assertIsNone(matching_compiled_run([], self.expected,
                                                lambda *_: None, lambda *_: []))


if __name__ == '__main__':
    unittest.main()
