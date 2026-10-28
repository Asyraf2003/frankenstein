import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'lib/control.py'
MOCK = '''import json, os, sys
name = os.path.basename(sys.argv[0])
with open(os.environ['CALLS'], 'a') as f: f.write(json.dumps([name, *sys.argv[1:]])+'\\n')
if name == 'sudo':
    os.execvp(sys.argv[2], sys.argv[2:])
key = name+' '+ ' '.join(sys.argv[1:])
response = json.loads(os.environ.get('RESPONSES', '{}')).get(key, {})
print(response.get('stdout', ''), end='')
print(response.get('stderr', ''), end='', file=sys.stderr)
sys.exit(response.get('code', int(os.environ.get('PROVIDER_EXIT', '0'))))
'''


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / 'bin'
        self.tools.mkdir()
        self.log = self.root / 'calls'
        self.env = {'PATH': str(self.tools), 'CALLS': str(self.log), 'PYTHONDONTWRITEBYTECODE': '1',
                    'HOME': str(self.root), 'LC_ALL': 'C'}
        for provider in ('sudo', 'pacman', 'systemctl', 'nmcli', 'bluetoothctl', 'rfkill'):
            path = self.tools / provider
            path.write_text('#!' + sys.executable + '\n' + MOCK)
            path.chmod(0o755)

    def run_cli(self, *args, responses=None, code=None):
        env = dict(self.env, RESPONSES=json.dumps(responses or {}))
        if code is not None:
            env['PROVIDER_EXIT'] = str(code)
        return subprocess.run([sys.executable, '-B', str(SCRIPT), *args], env=env,
                              capture_output=True, text=True, timeout=10)

    def calls(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_help_and_invalid_commands_never_touch_providers(self):
        self.assertEqual(self.run_cli('--help').returncode, 0)
        for args in [('power', 'reboot', '--force'), ('packages', 'install', '--overwrite=*'),
                     ('packages', 'remove', '/etc'), ('wifi', 'connect', 'name', 'password'),
                     ('bt', 'scan', '0'), ('bt', 'connect', 'invalid'), ('service', 'enable', 'sshd')]:
            self.assertNotEqual(self.run_cli(*args).returncode, 0, args)
        self.assertEqual(self.calls(), [])

    def test_package_install_always_full_upgrade_and_remove_no_recursive_flag(self):
        self.assertEqual(self.run_cli('packages', 'install', 'hello').returncode, 0)
        self.assertIn(['pacman', '-Syu', '--needed', '--', 'hello'], self.calls())
        self.assertEqual(self.run_cli('packages', 'remove', 'hello').returncode, 0)
        self.assertIn(['pacman', '-R', '--', 'hello'], self.calls())

    def test_package_no_updates_is_success_but_database_error_is_failure(self):
        self.assertEqual(self.run_cli('packages', 'status', responses={'pacman -Qu': {'code': 1}}).returncode, 0)
        self.assertEqual(self.run_cli('packages', 'status', responses={'pacman -Qu': {'code': 1, 'stderr': 'database error'}}).returncode, 1)

    def test_provider_exit_status_is_preserved(self):
        for args in [('packages', 'update'), ('power', 'suspend'), ('wifi', 'on'), ('bt', 'status')]:
            self.assertEqual(self.run_cli(*args, code=37).returncode, 37)

    def test_power_respects_native_authorization(self):
        for action in ('suspend', 'reboot', 'poweroff'):
            self.assertEqual(self.run_cli('power', action).returncode, 0)
        self.assertEqual(self.calls(), [['systemctl', x] for x in ('suspend', 'reboot', 'poweroff')])

    def test_wifi_selects_real_interface_and_never_accepts_password_argument(self):
        responses = {'nmcli -t --escape no -f DEVICE,TYPE device status': {'stdout': 'lo:loopback\nwlan9:wifi\n'}}
        self.assertEqual(self.run_cli('wifi', 'connect', 'Cafe: guest', responses=responses).returncode, 0)
        self.assertEqual(self.calls()[-1], ['nmcli', '--ask', 'device', 'wifi', 'connect', 'Cafe: guest', 'ifname', 'wlan9', 'private', 'yes'])
        self.assertEqual(self.run_cli('wifi', 'disconnect', responses=responses).returncode, 0)
        self.assertEqual(self.calls()[-1], ['nmcli', 'device', 'disconnect', 'wlan9'])

    def test_wifi_multiple_adapters_fail_before_connection_change(self):
        responses = {'nmcli -t --escape no -f DEVICE,TYPE device status': {'stdout': 'wlan0:wifi\nwlan1:wifi\n'}}
        self.assertNotEqual(self.run_cli('wifi', 'disconnect', responses=responses).returncode, 0)
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.run_cli('wifi', '--interface', 'wlan1', 'disconnect', responses=responses).returncode, 0)
        self.assertEqual(self.calls()[-1], ['nmcli', 'device', 'disconnect', 'wlan1'])

    def test_wifi_missing_device_and_provider_are_actionable(self):
        self.assertIn('absent or ambiguous', self.run_cli('wifi', 'disconnect').stderr)
        (self.tools/'nmcli').unlink()
        self.assertIn('missing provider', self.run_cli('wifi', 'status').stderr)

    def test_bluetooth_addresses_and_bounded_scan(self):
        address = '02:00:00:00:00:01'
        for action in ('pair', 'trust', 'untrust', 'remove', 'connect', 'disconnect', 'info'):
            self.assertEqual(self.run_cli('bt', action, address).returncode, 0)
            self.assertEqual(self.calls()[-1], ['bluetoothctl', action, address])
        self.assertEqual(self.run_cli('bt', 'scan', '30').returncode, 0)
        self.assertEqual(self.calls()[-1], ['bluetoothctl', '--timeout', '30', 'scan', 'on'])

    def test_bluetooth_ambiguous_controller_never_changes_radio(self):
        responses = {'bluetoothctl list': {'stdout': 'Controller A\nController B\n'}}
        self.assertNotEqual(self.run_cli('bt', 'on', responses=responses).returncode, 0)
        self.assertEqual(self.calls(), [['bluetoothctl', 'list']])

    def test_bluetooth_power_failure_does_not_claim_success_or_block_radio(self):
        responses = {'bluetoothctl list': {'stdout': 'Controller 02:00:00:00:00:01 test\n'},
                     'bluetoothctl power off': {'code': 9}}
        self.assertEqual(self.run_cli('bt', 'off', responses=responses).returncode, 9)
        self.assertFalse(any(x[0] == 'rfkill' for x in self.calls()))

    def test_service_enable_does_not_start_or_restart(self):
        self.assertEqual(self.run_cli('service', 'enable', 'network').returncode, 0)
        self.assertIn(['systemctl', 'enable', 'NetworkManager.service'], self.calls())
        self.assertNotIn('--now', str(self.calls()))


if __name__ == '__main__':
    unittest.main()
