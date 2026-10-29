import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('profiles', ROOT/'lib/profiles.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class ProfileTransactions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='frankenstein-profile-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root/'unrelated user'
        self.home.mkdir()
        self.assets = self.root/'assets'
        self.assets.mkdir()
        self.make_profile('one', {'a': ('.config/a', 'first'), 'b': ('.bashrc', 'shell')})
        self.make_profile('two', {'a': ('.config/a', 'second')})
        self.manager = p.Profiles(self.home, self.assets)

    def make_profile(self, name, files):
        root = self.assets/name
        root.mkdir()
        manifest = {'commands': [], 'files': {k: v[0] for k, v in files.items()}}
        (root/'manifest.json').write_text(json.dumps(manifest))
        for k, v in files.items():
            (root/k).write_text(v[1])

    def run_action(self, action, name=None, replace=False):
        return self.manager.run(argparse.Namespace(action=action, name=name, replace=replace))

    def test_read_only_status_creates_no_state(self):
        self.run_action('status')
        self.assertEqual(list(self.home.iterdir()), [])

    def test_apply_verify_idempotence_and_lifo_rollback(self):
        self.run_action('apply', 'one')
        generation = self.manager.current.read_bytes()
        self.run_action('apply', 'one')
        self.assertEqual(generation, self.manager.current.read_bytes())
        self.run_action('apply', 'two')
        self.assertEqual((self.home/'.config/a').read_text(), 'second')
        self.run_action('verify')
        self.run_action('rollback')
        self.assertEqual((self.home/'.config/a').read_text(), 'first')
        self.run_action('rollback')
        self.assertFalse((self.home/'.config/a').exists())
        self.assertFalse((self.home/'.bashrc').exists())

    def test_existing_file_requires_replace_and_original_mode_is_restored(self):
        target = self.home/'.bashrc'
        target.write_bytes(b'original\x00bytes')
        target.chmod(0o600)
        with self.assertRaises(p.Error): self.run_action('apply', 'one')
        self.assertFalse((self.home/'.config/a').exists())
        self.run_action('apply', 'one', True)
        self.run_action('rollback')
        self.assertEqual(target.read_bytes(), b'original\x00bytes')
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_drift_prevents_apply_and_rollback_without_partial_writes(self):
        self.run_action('apply', 'one')
        (self.home/'.bashrc').write_text('user edit')
        for action, name in [('apply', 'two'), ('rollback', None), ('verify', None)]:
            with self.assertRaises(p.Error): self.run_action(action, name)
        self.assertEqual((self.home/'.config/a').read_text(), 'first')

    def test_symlink_and_path_escape_are_refused(self):
        (self.home/'.config').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(p.Error): self.run_action('apply', 'one')
        self.assertFalse((self.root/'a').exists())
        for relative in ('../escape', '/tmp/escape', '.local/state/frankenstein/profiles/current.json'):
            with self.assertRaises(p.Error): self.manager.target(relative)

    def test_missing_dependency_blocks_all_file_changes(self):
        manifest = self.assets/'one/manifest.json'
        data = json.loads(manifest.read_text())
        data['commands'] = ['frankenstein-nonexistent-provider']
        manifest.write_text(json.dumps(data))
        with self.assertRaises(p.Error): self.run_action('apply', 'one')
        self.assertFalse((self.home/'.bashrc').exists())

    def interrupted_apply(self):
        original = p.restore
        calls = 0
        def interrupted(path, value):
            nonlocal calls
            calls += 1
            if calls == 2: raise OSError('simulated interrupted write')
            original(path, value)
        with patch.object(p, 'restore', interrupted):
            with self.assertRaises(OSError): self.run_action('apply', 'one')
        self.assertTrue(self.manager.pending.exists())

    def test_interrupted_apply_requires_recovery_and_restores_original(self):
        self.interrupted_apply()
        with self.assertRaises(p.Error): self.run_action('apply', 'two')
        self.run_action('recover')
        self.assertFalse((self.home/'.config/a').exists())
        self.assertFalse(self.manager.pending.exists())
        self.run_action('apply', 'one')

    def test_recovery_preserves_user_changes_after_interruption(self):
        self.interrupted_apply()
        (self.home/'.config/a').write_text('new user data')
        with self.assertRaises(p.Error): self.run_action('recover')
        self.assertEqual((self.home/'.config/a').read_text(), 'new user data')

    def test_shared_state_permissions_are_rejected(self):
        self.manager.state.mkdir(parents=True, mode=0o755)
        self.manager.state.chmod(0o755)
        with self.assertRaises(p.Error): self.run_action('apply', 'one')

    def test_shell_profile_is_noninteractive_safe_and_has_no_private_dispatch(self):
        import subprocess
        shell = ROOT/'profiles/shell/bashrc'
        result = subprocess.run(['bash', '--noprofile', '--norc', '-c', 'source "$1"; printf "%s" "$PATH"', 'test', str(shell)],
                                env={'PATH': '/usr/bin:/bin', 'HOME': str(self.home)}, capture_output=True, text=True)
        self.assertEqual(result.stdout, '/usr/bin:/bin')
        self.assertNotIn('ssh-agent', shell.read_text())

    def test_optional_shell_integrations_are_interactive_and_provider_guarded(self):
        import shutil
        import subprocess
        tools = self.root/'tools'
        tools.mkdir()
        bash = shutil.which('bash')
        shell = ROOT/'profiles/shell/bashrc'
        log = self.root/'calls'
        env = {'PATH': str(tools), 'HOME': str(self.home), 'CALLS': str(log), 'TERM': 'dumb'}
        def invoke(interactive):
            return subprocess.run([bash, '--noprofile', '--norc', '-ic' if interactive else '-c',
                                   'source "$1"; printf "%s:%s" "${ZOXIDE_READY:-absent}" "${FZF_READY:-absent}"',
                                   'test', str(shell)], env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(invoke(True).stdout, 'absent:absent')
        for name, argument, marker in (('zoxide', 'init bash', 'ZOXIDE_READY'), ('fzf', '--bash', 'FZF_READY')):
            provider = tools/name
            provider.write_text('#!/bin/sh\n' +
                                'test "$*" = "'+argument+'" || exit 99\n' +
                                'printf "%s\\n" "'+name+'" >> "$CALLS"\n' +
                                'printf "%s\\n" "export '+marker+'=ready"\n')
            provider.chmod(0o755)
        self.assertEqual(invoke(False).stdout, 'absent:absent')
        self.assertFalse(log.exists())
        result = invoke(True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'ready:ready')
        self.assertEqual(log.read_text().splitlines(), ['zoxide', 'fzf'])


if __name__ == '__main__':
    unittest.main()
