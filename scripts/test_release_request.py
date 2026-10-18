import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import release_request as request


class ReleaseRequest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'test')
        self.git('config', 'user.email', 'test@example.invalid')
        (self.root / 'README').write_text('initial')
        self.before = self.commit()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True).strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def put_request(self, value=None):
        path = self.root / request.REQUEST
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(value or dict(schema=1, version='v0.1.0-alpha.1')))
        return self.commit()

    def resolve(self, after, event='push', ref='refs/heads/main', before=None):
        return request.resolve(self.root, event, ref, before or self.before, after)

    def test_main_request_publishes_but_pr_and_feature_do_not(self):
        after = self.put_request()
        self.assertEqual(dict(version='v0.1.0-alpha.1', publish='true', source='request'), self.resolve(after))
        for event, ref in [('pull_request', 'refs/pull/10/merge'), ('push', 'refs/heads/feature/release')]:
            with self.subTest(event=event, ref=ref):
                self.assertEqual('false', self.resolve(after, event, ref)['publish'])

    def test_ordinary_main_push_does_not_repeat_release(self):
        before = self.put_request()
        (self.root / 'README').write_text('unrelated')
        after = self.commit()
        self.assertEqual(dict(version='v0.0.0-ci', publish='false', source='ci'), self.resolve(after, before=before))

    def test_version_bump_is_a_new_request(self):
        before = self.put_request()
        after = self.put_request(dict(schema=1, version='v0.1.0-alpha.2'))
        self.assertEqual('v0.1.0-alpha.2', self.resolve(after, before=before)['version'])

    def test_existing_tag_flow_and_absent_request(self):
        self.assertEqual('false', self.resolve(self.before)['publish'])
        self.assertEqual(dict(version='v0.2.0-rc.1', publish='true', source='tag'),
                         self.resolve(self.before, ref='refs/tags/v0.2.0-rc.1'))

    def test_malformed_request_fails_even_in_pr(self):
        for data in [dict(schema=True, version='v1.0.0'), dict(schema=2, version='v1.0.0'),
                     dict(schema=1, version='v0.0.0-ci'), dict(schema=1, version='v1.0.0\npublish=true'),
                     dict(schema=1, version='v1.0.0', publish=True)]:
            with self.subTest(data=data):
                after = self.put_request(data)
                with self.assertRaises(ValueError):
                    self.resolve(after, event='pull_request')

    def test_unknown_history_cannot_publish(self):
        after = self.put_request()
        for before in ['0' * 40, 'bad', 'f' * 40]:
            with self.subTest(before=before), self.assertRaises(ValueError):
                self.resolve(after, before=before)


if __name__ == '__main__':
    unittest.main()
