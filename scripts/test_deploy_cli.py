import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import deploy_cli as deploy
import test_release


class DeploymentContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.deployment = deploy.Deployment(self.base / 'home')
        self.source = self.base / 'candidate'
        self.source.write_bytes(b'first-binary')
        self.identity = deploy.digest(self.source)
        self.info = dict(schema=1, version='v0.0.0-lab.1', commit='a' * 40, dirty=False,
                         protocol_draft=deploy.contract.DRAFT, build_flavor='go',
                         goos=deploy.target()[0], goarch=deploy.target()[1])
        self.output = patch.object(deploy.subprocess, 'check_output', side_effect=lambda *a, **kw: json.dumps(self.info).encode())
        self.output.start()
        self.addCleanup(self.output.stop)

    def install(self):
        return self.deployment.install(self.source, deploy.digest(self.source), self.info['version'], self.info['commit'])

    def next_release(self):
        self.source.write_bytes(b'second-binary')
        self.info['version'] = 'v0.0.0-lab.2'
        return deploy.digest(self.source)

    def test_update_rollback_preserves_configuration_and_detects_modification(self):
        config = self.deployment.config / 'connection.txt'
        config.write_bytes(b'PRIVATE-CONNECTION-DO-NOT-REWRITE')
        before = (config.read_bytes(), config.stat().st_mode)
        self.install()
        new = self.next_release()
        self.install()
        self.assertEqual(self.deployment.state()['active'], new)
        self.deployment.rollback()
        self.assertEqual(self.deployment.state()['active'], self.identity)
        self.assertEqual((config.read_bytes(), config.stat().st_mode), before)
        executable, _ = self.deployment.bundle(self.identity)
        executable.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'modified'):
            self.deployment.bundle(self.identity)

    def test_hash_and_metadata_failures_do_not_activate(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.deployment.install(self.source, 'f' * 64, self.info['version'], 'a' * 40)
        for key, value in [('dirty', True), ('schema', True), ('goarch', 'wrong'), ('build_flavor', 'nss')]:
            original = self.info[key]
            self.info[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.install()
            self.info[key] = original
        self.assertIsNone(self.deployment.state()['active'])

    def test_failed_commit_retains_activation_and_explicit_recovery_repairs_state(self):
        self.install()
        before = self.deployment.state_path.read_bytes()
        new = self.next_release()
        write = deploy.atomic_json
        def fail_state(path, content):
            if path == self.deployment.state_path:
                raise OSError('injected write failure')
            write(path, content)
        with patch.object(deploy, 'atomic_json', side_effect=fail_state):
            with self.assertRaises(OSError):
                self.install()
        self.assertEqual(self.deployment.state_path.read_bytes(), before)
        self.deployment.state_path.write_bytes(b'broken-state')
        self.deployment.recover(new)
        self.assertEqual(self.deployment.state()['active'], new)
        self.assertIsNone(self.deployment.state()['previous'])

    def test_lock_blocks_other_process_and_releases_after_exit(self):
        code = "import sys;sys.path.insert(0,sys.argv[1]);import deploy_cli;d=deploy_cli.Deployment(sys.argv[2]);\nwith d.lock(): pass"
        command = [sys.executable, '-c', code, str(Path(deploy.__file__).parent), str(self.deployment.root)]
        # Avoid using our mocked check_output; this is an actual OS lock.
        with self.deployment.lock():
            result = subprocess.run(command, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(subprocess.run(command, capture_output=True, timeout=5).returncode, 0)

    def test_no_previous_and_unsafe_pointers_are_rejected(self):
        with self.assertRaises(ValueError):
            self.deployment.rollback()
        deploy.atomic_json(self.deployment.state_path, {'schema': 1, 'active': '../config', 'previous': None})
        with self.assertRaises(ValueError):
            self.deployment.state()
        with self.assertRaises(ValueError):
            self.deployment.recover('../config')

    def test_complete_nss_archive_and_unsafe_archive_rejection(self):
        fixture = test_release.ReleaseContract()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        index = fixture.find('linux/amd64/nss')
        metadata = json.loads(fixture.entries[index].read_text())
        source = fixture.root / metadata['filename']
        self.info.update(version=metadata['version'], goos='linux', goarch='amd64', build_flavor='nss')
        with patch.object(deploy, 'target', return_value=('linux', 'amd64')):
            self.deployment.install(source, deploy.digest(source), metadata['version'], 'a' * 40, True)
            executable, record = self.deployment.bundle(deploy.digest(source))
            self.assertEqual((executable.parent / 'lib/libnss3.so').read_bytes(), b'library')
            self.assertIn('mozilla-runtime.json', record['files'])
            fixture.pack(index, lambda files: files.update({'../escape': b'bad'}))
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                self.deployment.install(source, deploy.digest(source), metadata['version'], 'a' * 40, True)
        self.assertFalse((self.deployment.root / 'escape').exists())


class LauncherLifecycle(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux executable write exclusion')
    def test_sync_bundle_while_executable_is_running(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            executable = bundle / 'sleep'
            shutil.copy2('/bin/sleep', executable)
            child = subprocess.Popen([str(executable), '30'])
            try:
                with self.assertRaises(OSError) as error:
                    executable.open('r+b')
                self.assertEqual(error.exception.errno, 26)
                deploy.sync_bundle(bundle)
            finally:
                child.terminate()
                child.wait(timeout=5)

    def test_windows_launcher_waits_for_child_and_preserves_exit_status(self):
        # A real child publishes its final marker shortly before exiting. The
        # launcher must remain waitable until both events have happened.
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / 'completed'
            code = "import pathlib,sys,time;time.sleep(.1);pathlib.Path(sys.argv[1]).write_text('done');sys.exit(7)"
            with patch.object(deploy.sys, 'platform', 'win32'):
                status = deploy.launch(sys.executable, ['-c', code, str(marker)])
            self.assertEqual(status, 7)
            self.assertEqual(marker.read_text(), 'done')

    def test_posix_launcher_retains_exec_argument_boundaries(self):
        with patch.object(deploy.sys, 'platform', 'linux'), patch.object(deploy.os, 'execv') as execute:
            deploy.launch('/reviewed/vetroff', ['version', 'argument with spaces'])
        execute.assert_called_once_with('/reviewed/vetroff', ['/reviewed/vetroff', 'version', 'argument with spaces'])


@unittest.skipUnless(os.environ.get('FOXTUNNEL_INSTALL_LAB_A') and os.environ.get('FOXTUNNEL_INSTALL_LAB_B'), 'native binaries supplied only by explicit installation lab')
class NativeInstallationLab(unittest.TestCase):
    def test_install_update_failed_update_rollback_and_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'install'
            manager = deploy.Deployment(root)
            config = manager.config / 'operator-secret.txt'
            config.write_bytes(os.urandom(64))
            config_before = (config.read_bytes(), config.stat().st_mode)
            binaries = [Path(os.environ[key]).resolve() for key in ('FOXTUNNEL_INSTALL_LAB_A', 'FOXTUNNEL_INSTALL_LAB_B')]
            commit = os.environ['FOXTUNNEL_INSTALL_LAB_COMMIT']
            for i, binary in enumerate(binaries, 1):
                manager.install(binary, deploy.digest(binary), f'v0.0.0-stage7.{i}', commit)
                active, _ = manager.bundle(manager.state()['active'])
                info = json.loads(subprocess.check_output([str(active), 'version', '--json'], timeout=10))
                self.assertEqual(info['version'], f'v0.0.0-stage7.{i}')
            good_state = manager.state_path.read_bytes()
            with self.assertRaises(ValueError):
                manager.install(binaries[0], 'f' * 64, 'v0.0.0-stage7.1', commit)
            self.assertEqual(manager.state_path.read_bytes(), good_state)
            manager.rollback()
            active, _ = manager.bundle(manager.state()['active'])
            self.assertEqual(json.loads(subprocess.check_output([str(active), 'version', '--json']))['version'], 'v0.0.0-stage7.1')
            manager.state_path.write_bytes(b'interrupted/corrupt activation')
            manager.recover(deploy.digest(binaries[1]))
            launcher = [sys.executable, str(Path(deploy.__file__).resolve()), '--root', str(root), 'run', '--', 'version', '--json']
            self.assertEqual(json.loads(subprocess.check_output(launcher, timeout=15))['version'], 'v0.0.0-stage7.2')
            self.assertEqual((config.read_bytes(), config.stat().st_mode), config_before)


if __name__ == '__main__':
    unittest.main()
