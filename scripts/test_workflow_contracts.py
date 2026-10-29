"""Keep reusable workflow references valid after workflow cleanup."""
from pathlib import Path
import re
import unittest


class WorkflowContracts(unittest.TestCase):
    def test_local_called_workflows_exist_and_accept_calls(self):
        root = Path(__file__).resolve().parents[1]
        for path in (root / '.github/workflows').glob('*.yml'):
            for target in re.findall(r'^\s+uses: (\./\S+)', path.read_text(), re.M):
                with self.subTest(caller=path.name, target=target):
                    called = root / target
                    self.assertTrue(called.is_file(), 'missing reusable workflow')
                    self.assertRegex(called.read_text(), r'(?m)^  workflow_call:')

    def test_source_and_runtime_artifact_names_do_not_collide(self):
        root = Path(__file__).resolve().parents[1] / '.github/workflows'
        names = lambda file: set(re.findall(r'^          name: (.+)$', (root / file).read_text(), re.M))
        # Source archives/provenance are intentionally downloaded by the consumer.
        source = names('necko-experiment.yml')
        runtime = names('necko-runtime-test.yml')
        self.assertEqual({'necko-linux-${{ matrix.arch }}-runtime',
                          'necko-source-provenance${{ matrix.suffix }}'}, source & runtime)


if __name__ == '__main__':
    unittest.main()
