"""Unprivileged safety checks for the native Linux VPN launcher."""
import json
import subprocess
import unittest
from unittest.mock import patch

import linux_native_vpn as native


class NativeNetworkTests(unittest.TestCase):
    def network(self, **kwargs):
        return native.Network(['198.18.0.1:8443', '[fd42:1::1]:8443'],
                              'wan0', 'ftun0', '198.18.0.9', **kwargs)

    def test_rejects_dns_on_carrier_bypass(self):
        with self.assertRaisesRegex(ValueError, 'DNS must differ'):
            native.Network(['198.18.0.1:8443'], 'wan0', 'ftun0', '198.18.0.1')

    def preflight_command(self, *args, check=True):
        result = subprocess.CompletedProcess(args, 0, '', '')
        if args[:3] == ('nft', 'list', 'table') or args == ('ip', 'link', 'show', 'dev', 'ftun0'):
            result.returncode = 1
        if 'rule' in args:
            result.stdout = json.dumps([{'priority': 0}, {'priority': 32766}, {'priority': 32767}])
        if 'get' in args:
            result.stdout = '[{"dev":"wan0"}]'
        return result

    def test_preflight_does_not_change_network(self):
        with patch.object(native.shutil, 'which', return_value='/bin/tool'), patch.object(native, 'command', side_effect=self.preflight_command) as run:
            self.network(dns_mode='none').preflight()
        for call in run.call_args_list:
            self.assertFalse({'add', 'del', 'set', '-f'} & set(call.args))

    def test_refuses_existing_guard_or_policy_rules(self):
        for conflict in ('guard', 'policy', 'table', 'uplink'):
            def run(*args, check=True):
                result = self.preflight_command(*args, check=check)
                if conflict == 'guard' and args[:3] == ('nft', 'list', 'table'):
                    result.returncode = 0
                if conflict == 'policy' and 'rule' in args:
                    result.stdout = '[{"priority":100}]'
                if conflict == 'table' and 'route' in args and 'show' in args:
                    result.stdout = 'default dev existing0'
                if conflict == 'uplink' and 'get' in args:
                    result.stdout = '[{"dev":"wrong0"}]'
                return result
            with self.subTest(conflict=conflict), patch.object(native.shutil, 'which', return_value='/bin/tool'), patch.object(native, 'command', side_effect=run):
                with self.assertRaises(ValueError):
                    self.network(dns_mode='none').preflight()

    def test_partial_route_failure_rolls_back_without_removing_guard(self):
        calls = []
        def run(*args, check=True):
            calls.append(args)
            if args[:4] == ('ip', '-6', 'addr', 'add'):
                raise subprocess.CalledProcessError(2, args)
            return subprocess.CompletedProcess(args, 0)
        network = self.network(dns_mode='none')
        with patch.object(native, 'command', side_effect=run):
            with self.assertRaises(subprocess.CalledProcessError):
                network.configure()
            network.close()
            network.close()
        adds = [c for c in calls if 'add' in c and c[:2] == ('ip', '-4')]
        deletes = [c for c in calls if 'del' in c]
        self.assertEqual(len(adds), len(deletes))
        self.assertFalse(any('nft' in c for c in calls))
        self.assertFalse(any('flush' in c for c in calls))

    def test_dual_stack_bypass_dns_and_cleanup(self):
        network = self.network()
        with patch.object(native, 'command', return_value=subprocess.CompletedProcess([], 0)) as run:
            network.configure()
            network.close()
        calls = [c.args for c in run.call_args_list]
        for family, endpoint in (('-4', '198.18.0.1'), ('-6', 'fd42:1::1')):
            self.assertTrue(any(c[:4] == ('ip', family, 'rule', 'add') and endpoint in c and 'main' in c for c in calls))
            self.assertTrue(any(c[:4] == ('ip', family, 'rule', 'add') and '51821' in c for c in calls))
        self.assertIn(('resolvectl', 'dns', 'ftun0', '198.18.0.9'), calls)
        self.assertIn(('resolvectl', 'domain', 'ftun0', '~.'), calls)
        self.assertIn(('resolvectl', 'revert', 'ftun0'), calls)
        self.assertFalse(any('flush' in c or 'replace' in c for c in calls))

    def test_refuses_unmanaged_resolver(self):
        with patch.object(native.shutil, 'which', return_value='/bin/tool'), patch.object(native, 'command', side_effect=self.preflight_command), patch.object(native.os.path, 'realpath', return_value='/etc/resolv.conf'):
            with self.assertRaisesRegex(ValueError, 'systemd-resolved'):
                self.network().preflight()


if __name__ == '__main__':
    unittest.main()
