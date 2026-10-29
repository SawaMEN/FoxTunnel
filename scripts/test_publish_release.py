import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import publish_release as publisher

OLD = 'a' * 40
NEW = 'b' * 40


class Publication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.names = [f'vetroff_0.1.0_linux_{arch}.tar.gz' for arch in ('amd64', 'arm64')]
        for name in self.names:
            (self.root / name).write_bytes(b'verified archive fixture')
        self.notes = self.root / 'notes.md'
        self.notes.write_text('new notes')
        self.assets = {1: self.names[0], 2: self.names[1]}
        self.sha = OLD
        self.fail = None
        self.calls = []

    def gh(self, *args):
        self.calls.append(args)
        if args[:2] == ('repo', 'view'):
            return 'test/repo'
        if args[:2] == ('release', 'upload'):
            for path in args[3:]:
                self.assets[max(self.assets) + 1] = Path(path).name
            return ''
        if args[:2] == ('release', 'edit'):
            if self.fail == 'notes':
                raise RuntimeError('edit failed')
            return ''
        if args[0] != 'api':
            raise AssertionError(args)
        if args[1] == '--method':
            method, path = args[2:4]
            if 'releases/assets/' in path:
                key = int(path.rsplit('/', 1)[1])
                if method == 'DELETE':
                    del self.assets[key]
                else:
                    name = args[5].removeprefix('name=')
                    if name in self.assets.values():
                        raise AssertionError('duplicate asset name')
                    self.assets[key] = name
            elif '/git/refs/' in path:
                self.sha = args[5].removeprefix('sha=')
            else:
                raise AssertionError(args)
            return ''
        path = args[1]
        if '/releases/tags/' in path:
            return json.dumps(dict(id=10, tag_name='v0.1.0', immutable=False, draft=False,
                                   assets=[dict(id=i, name=n) for i, n in self.assets.items()]))
        if '/git/refs/' in path:
            return json.dumps(dict(object=dict(type='commit', sha=self.sha)))
        if path.endswith('/assets'):
            return json.dumps([dict(id=i, name=n) for i, n in self.assets.items()])
        raise AssertionError(args)

    def publish(self):
        with patch.object(publisher, 'gh', self.gh):
            publisher.publish('v0.1.0', NEW, 'replacement', OLD, self.notes, self.root)

    def test_promote_both_uploads_before_deleting_previous_assets(self):
        self.publish()
        self.assertEqual(NEW, self.sha)
        self.assertEqual(set(self.names), set(self.assets.values()))
        self.assertEqual({3, 4}, set(self.assets))
        self.assertTrue(all(args[2] == 'DELETE' for args in self.calls[-2:]))

    def test_failed_promotion_restores_old_names_and_tag(self):
        self.fail = 'notes'
        with self.assertRaisesRegex(RuntimeError, 'edit failed'):
            self.publish()
        self.assertEqual(OLD, self.sha)
        self.assertEqual(self.names, [self.assets[1], self.assets[2]])
        self.assertFalse(any('DELETE' in args for args in self.calls))

    def test_changed_tag_aborts_before_upload(self):
        self.sha = 'c' * 40
        with self.assertRaisesRegex(ValueError, 'tag changed'):
            self.publish()
        self.assertFalse(any(args[:2] == ('release', 'upload') for args in self.calls))

    def test_missing_architecture_aborts_without_network(self):
        (self.root / self.names[1]).unlink()
        with self.assertRaisesRegex(ValueError, 'exactly two'):
            self.publish()
        self.assertEqual([], self.calls)


if __name__ == '__main__':
    unittest.main()
