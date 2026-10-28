"""Audio contracts adapted from upstream MIT tests; all providers are isolated."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash')
AUDIO = {'vol': '@DEFAULT_AUDIO_SINK@', 'mic': '@DEFAULT_AUDIO_SOURCE@'}
MOCK = '''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as f: f.write(json.dumps(args)+'\\n')
if os.environ.get('FAIL'): sys.exit(int(os.environ['FAIL']))
path = Path(os.environ['STATE'])
state = json.loads(path.read_text())
if args[0] == 'set-volume': state[args[-2]]['volume'] = int(args[-1][:-1])
elif args[0] == 'set-mute': state[args[1]]['muted'] = args[2] == '1'
elif args[0] == 'get-volume':
    node = state[args[1]]
    print(f'Volume: {node["volume"] / 100:.2f}' + (' [MUTED]' if node['muted'] else ''))
    sys.exit(0)
else: raise AssertionError(args)
path.write_text(json.dumps(state))
'''


class Audio(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.calls = self.root / 'calls'
        self.state = self.root / 'state'
        self.state.write_text(json.dumps({n: {'volume': 50, 'muted': False} for n in AUDIO.values()}))
        self.env = {'PATH': str(self.root), 'HOME': str(self.root), 'LC_ALL': 'C',
                    'CALLS': str(self.calls), 'STATE': str(self.state)}
        provider = self.root / 'wpctl'
        provider.write_text('#!' + sys.executable + '\n' + MOCK)
        provider.chmod(0o755)

    def invoke(self, name, *args):
        return subprocess.run([BASH, str(ROOT / 'bin' / name), *args], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def test_entire_integer_range_and_default_device(self):
        for name, node in AUDIO.items():
            for percent in range(101):
                result = self.invoke(name, str(percent))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(self.calls.read_text().splitlines()[-1]),
                                 ['set-volume', '-l', '1.0', node, f'{percent}%'])

    def test_leading_zeros_are_decimal(self):
        for name in AUDIO:
            for value in ('000', '008', '010', '099'):
                self.assertEqual(self.invoke(name, value).returncode, 0)
                self.assertEqual(json.loads(self.calls.read_text().splitlines()[-1])[-1], f'{int(value)}%')

    def test_invalid_input_never_reaches_provider(self):
        before = self.state.read_bytes()
        for name in AUDIO:
            for value in ('', '-1', '+1', '101', '999', '1000', '0000', '9'*1000,
                          '1.5', '1e2', '0x10', '50%', '50%+', ' 50', '50\n',
                          'STATUS', 'toggle', '--device=x', '1; touch sentinel',
                          '$(touch sentinel)', '`touch sentinel`', 'a[0]=100', '０', '١'):
                self.assertEqual(self.invoke(name, value).returncode, 2, value)
            for args in (('50', '60'), ('status', 'extra'), ('--help', 'extra')):
                self.assertEqual(self.invoke(name, *args).returncode, 2)
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.state.read_bytes(), before)

    def test_status_is_read_only_and_mute_is_idempotent(self):
        before = self.state.read_bytes()
        for name in AUDIO:
            for args in ((), ('status',)):
                self.assertEqual(self.invoke(name, *args).stdout, 'Volume: 0.50\n')
                self.assertEqual(self.state.read_bytes(), before)
        for name in AUDIO:
            for action, muted in (('mute', True), ('unmute', False)):
                for _ in range(2):
                    self.assertEqual(self.invoke(name, action).returncode, 0)
                    self.assertEqual('[MUTED]' in self.invoke(name, 'status').stdout, muted)
            self.assertEqual(self.invoke(name, 'mute').returncode, 0)
            self.assertEqual(self.invoke(name, '80').returncode, 0)
            self.assertEqual(self.invoke(name).stdout, 'Volume: 0.80 [MUTED]\n')

    def test_failures_and_help_without_provider(self):
        self.env['FAIL'] = '37'
        for name in AUDIO:
            self.assertEqual(self.invoke(name, 'status').returncode, 37)
        (self.root / 'wpctl').unlink()
        for name in AUDIO:
            self.assertEqual(self.invoke(name, 'status').returncode, 127)
            self.assertEqual(self.invoke(name, '101').returncode, 2)
            self.assertEqual(self.invoke(name, '--help').returncode, 0)


class Session(unittest.TestCase):
    def test_missing_display_and_profile_fail_before_session_start(self):
        with tempfile.TemporaryDirectory() as home:
            env = {'PATH': '', 'HOME': home}
            command = [BASH, str(ROOT / 'bin/frankenstein-openbox')]
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('display', result.stderr)
            env['DISPLAY'] = ':99'
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('profile', result.stderr)

    def test_session_bus_reused_or_created_without_other_side_effects(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            config = root / '.config/openbox'
            config.mkdir(parents=True)
            (config / 'rc.xml').touch()
            for name in ('dbus-run-session', 'openbox-session'):
                path = root / name
                path.write_text('#!/bin/sh\nprintf "%s\\n" "$0" "$@" "$XDG_SESSION_TYPE" "$XDG_CURRENT_DESKTOP"\n')
                path.chmod(0o755)
            env = {'PATH': home, 'HOME': home, 'DISPLAY': ':99'}
            command = [BASH, str(ROOT / 'bin/frankenstein-openbox')]
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.splitlines(), [home+'/dbus-run-session', '--', 'openbox-session', 'x11', 'Openbox'])
            env['DBUS_SESSION_BUS_ADDRESS'] = 'test-only'
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.splitlines(), [home+'/openbox-session', 'x11', 'Openbox'])
