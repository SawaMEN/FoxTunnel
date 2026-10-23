import unittest
from unittest.mock import patch
import check_core_boundaries as boundaries


class BoundariesTests(unittest.TestCase):
    def run_graph(self, packages, modules=()):
        with patch.object(boundaries.subprocess, 'check_output', side_effect=[
                '\n'.join(packages), '\n'.join(modules)]):
            boundaries.check()

    def test_owned_necko_api_is_promoted(self):
        self.run_graph([boundaries.MODULE, boundaries.MODULE + '/experiments/firefox-necko'])

    def test_research_tools_and_new_subpackages_remain_forbidden(self):
        for suffix in ('experiments/firefox-necko/fingerprint',
                       'experiments/unreviewed', 'internal/fingerprint',
                       'cmd/ft-fingerprint', 'internal/webprofile'):
            with self.subTest(suffix=suffix), self.assertRaises(SystemExit):
                self.run_graph([boundaries.MODULE + '/experiments/firefox-necko',
                                boundaries.MODULE + '/' + suffix])

    def test_host_vpn_dependencies_still_fail(self):
        for module in boundaries.HOST_MODULES:
            with self.subTest(module=module), self.assertRaises(SystemExit):
                self.run_graph([boundaries.MODULE], [module])


if __name__ == '__main__':
    unittest.main()
