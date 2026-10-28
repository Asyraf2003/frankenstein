#!/usr/bin/env python3
# Adapted from MIT-licensed CLI implementations, Copyright (c) 2026 Asyraf.
# See /usr/share/licenses/frankenstein-core/upstream-MIT.
"""Arch-native package, power, network and profile controls."""
import os
import re
import shutil
import subprocess
import sys


class Error(Exception):
    pass


HELP = """Usage: frankenstein COMMAND [ARGS]
  packages status|update|install PACKAGE...|remove PACKAGE...
  power status|suspend|reboot|poweroff
  wifi [--interface DEVICE] status|on|off|list|saved|disconnect|connect SSID
  bt status|on|off|list|paired|scan [SECONDS]|connect|disconnect|pair|trust|untrust|remove|info ADDRESS
  service status|enable|disable network|bluetooth
  profile list|status|verify|apply NAME [--replace]|rollback|recover

Install/remove/update use pacman; installation performs a full system upgrade.
Power actions use systemd/logind and its normal authorization and inhibitors.
Wi-Fi requires NetworkManager; Bluetooth requires BlueZ and util-linux.
Connect prompts for credentials through nmcli; credentials are never arguments.
Service enable/disable changes boot enablement only; start/stop through systemctl.
Profiles manage only the current user's files. Apply refuses existing files unless
--replace is explicitly selected; backups and rollback preserve previous bytes.
Rollback affects profile files only, never packages, services or user data.
Desktop profiles are optional. No private repository or recovery input is needed.
"""


def call(args, capture=False, privileged=False):
    if not shutil.which(args[0]):
        raise Error('missing provider: ' + args[0])
    if privileged and os.geteuid() != 0:
        if not shutil.which('sudo'):
            raise Error('this action needs root or sudo')
        args = ['sudo', '--', *args]
    return subprocess.run(args, text=True, capture_output=capture, check=False)


def checked(args):
    result = call(args, capture=True)
    if result.returncode:
        raise Error(result.stderr.strip() or 'provider failed: ' + args[0])
    return result.stdout.strip()


def packages(args):
    if args == ['status']:
        result = call(['pacman', '-Qu'], capture=True)
        print(result.stdout, end='')
        print(result.stderr, end='', file=sys.stderr)
        return 0 if result.returncode == 1 and not result.stdout and not result.stderr else result.returncode
    if args == ['update']:
        return call(['pacman', '-Syu'], privileged=True).returncode
    if len(args) >= 2 and args[0] in ('install', 'remove'):
        if not all(re.fullmatch(r'[a-zA-Z0-9@_+][a-zA-Z0-9@_.+-]*', x) for x in args[1:]):
            raise Error('invalid package name; flags and paths are not accepted')
        flags = ['-Syu', '--needed'] if args[0] == 'install' else ['-R']
        return call(['pacman', *flags, '--', *args[1:]], privileged=True).returncode
    raise Error('expected packages status|update|install PACKAGE...|remove PACKAGE...')


def power(args):
    if not args or args == ['status']:
        return call(['systemctl', 'is-system-running']).returncode
    if len(args) == 1 and args[0] in ('suspend', 'reboot', 'poweroff'):
        # No sudo or forced/inhibitor-bypassing flags: native authorization owns this.
        return call(['systemctl', args[0]]).returncode
    raise Error('expected power status|suspend|reboot|poweroff')


def wifi(args):
    args = list(args)
    device = None
    if args[:1] == ['--interface']:
        if len(args) < 3 or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', args[1]):
            raise Error('expected --interface DEVICE followed by an action')
        device, args = args[1], args[2:]
    action = args[0] if args else 'status'
    if action not in ('status', 'on', 'off', 'list', 'saved', 'disconnect', 'connect'):
        raise Error('unsupported Wi-Fi action')
    expected = 2 if action == 'connect' else 1
    if args and len(args) != expected:
        raise Error('invalid Wi-Fi arguments; connect takes only SSID')
    if action == 'connect' and (not args[1] or len(args[1].encode()) > 32 or '\n' in args[1]):
        raise Error('SSID must be 1..32 bytes without newlines')
    if action in ('on', 'off'):
        if device:
            raise Error('radio on/off is global; omit --interface')
        return call(['nmcli', 'radio', 'wifi', action]).returncode
    if action == 'saved':
        if device:
            raise Error('saved lists profiles; omit --interface')
        return call(['nmcli', '-f', 'NAME,TYPE,DEVICE', 'connection', 'show']).returncode
    if action == 'status' and not device:
        return call(['nmcli', 'device', 'status']).returncode
    output = checked(['nmcli', '-t', '--escape', 'no', '-f', 'DEVICE,TYPE', 'device', 'status'])
    devices = [line.rsplit(':', 1)[0] for line in output.splitlines() if line.endswith(':wifi')]
    if device is None:
        if len(devices) != 1:
            raise Error('select --interface: Wi-Fi device is absent or ambiguous')
        device = devices[0]
    if device not in devices:
        raise Error('selected device is not a NetworkManager Wi-Fi interface')
    if action == 'status':
        command = ['nmcli', 'device', 'show', device]
    elif action == 'list':
        command = ['nmcli', 'device', 'wifi', 'list', 'ifname', device]
    elif action == 'disconnect':
        command = ['nmcli', 'device', 'disconnect', device]
    else:
        command = ['nmcli', '--ask', 'device', 'wifi', 'connect', args[1], 'ifname', device, 'private', 'yes']
    return call(command).returncode


def bluetooth(args):
    action = args[0] if args else 'status'
    simple = {'status': ['show'], 'list': ['devices'], 'paired': ['devices', 'Paired']}
    address_actions = ('connect', 'disconnect', 'pair', 'trust', 'untrust', 'remove', 'info')
    if action in address_actions:
        if len(args) != 2 or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', args[1]):
            raise Error('expected a Bluetooth device address')
        return call(['bluetoothctl', action, args[1]]).returncode
    if action == 'scan':
        if len(args) > 2 or (len(args) == 2 and not re.fullmatch(r'[0-9]{1,3}', args[1])):
            raise Error('scan duration must be 1..300 seconds')
        seconds = int(args[1]) if len(args) == 2 else 10
        if not 1 <= seconds <= 300:
            raise Error('scan duration must be 1..300 seconds')
        return call(['bluetoothctl', '--timeout', str(seconds), 'scan', 'on']).returncode
    if len(args) > 1 or action not in (*simple, 'on', 'off'):
        raise Error('unsupported Bluetooth action or arguments')
    if action in simple:
        return call(['bluetoothctl', *simple[action]]).returncode
    # Resolve exactly one native controller before touching the radio.
    controllers = checked(['bluetoothctl', 'list']).splitlines()
    if len([x for x in controllers if x.startswith('Controller ')]) != 1:
        raise Error('exactly one Bluetooth controller is required; use bluetoothctl for multi-controller setup')
    if action == 'on':
        result = call(['rfkill', 'unblock', 'bluetooth'], privileged=True)
        if result.returncode:
            return result.returncode
    result = call(['bluetoothctl', 'power', action])
    if result.returncode:
        return result.returncode
    if action == 'off':
        return call(['rfkill', 'block', 'bluetooth'], privileged=True).returncode
    return 0


def service(args):
    units = {'network': 'NetworkManager.service', 'bluetooth': 'bluetooth.service'}
    if len(args) != 2 or args[0] not in ('status', 'enable', 'disable') or args[1] not in units:
        raise Error('expected service status|enable|disable network|bluetooth')
    action, name = args
    if action == 'status':
        return call(['systemctl', 'status', '--no-pager', units[name]]).returncode
    return call(['systemctl', action, units[name]], privileged=True).returncode


def main(args):
    if not args or args in (['--help'], ['-h']):
        print(HELP)
        return 0
    if args[0] == 'profile':
        import profiles
        return profiles.main(args[1:])
    handlers = {'packages': packages, 'power': power, 'wifi': wifi, 'bt': bluetooth, 'service': service}
    if args[0] not in handlers:
        raise Error('unknown command; use frankenstein --help')
    return handlers[args[0]](args[1:])


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except (Error, OSError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
