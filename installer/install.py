#!/usr/bin/env python3
"""Arch installation adapter. Nothing mutates a disk without interactive approval."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

PAYLOAD = Path('/opt/frankenstein')
TARGET = Path('/mnt/frankenstein')
MAPPER = 'frankenstein-root'
BASE = ['base', 'linux', 'linux-lts', 'linux-firmware', 'mkinitcpio', 'cryptsetup',
        'e2fsprogs', 'dosfstools', 'sudo', 'networkmanager', 'python', 'git',
        'openbox', 'xorg-server', 'xorg-xinit', 'xorg-xsetroot', 'dbus', 'python-pyxdg',
        'xterm', 'thunar', 'rofi', 'dunst', 'ttf-dejavu', 'playerctl', 'pipewire',
        'pipewire-pulse', 'wireplumber', 'polkit']


class Error(Exception):
    pass


def run(*args, capture=False, secret=None):
    # Never log stdin, which may contain provisioning secrets.
    result = subprocess.run([str(x) for x in args], input=secret, text=True,
                            stdout=subprocess.PIPE if capture else None, check=False)
    if result.returncode:
        raise Error('provider failed: ' + str(args[0]))
    return result.stdout.strip() if capture else ''


def inventory():
    return json.loads(run('lsblk', '--json', '--bytes', '--paths', '--output',
                         'NAME,TYPE,SIZE,MODEL,SERIAL,WWN,MAJ:MIN,RO,MOUNTPOINTS,FSTYPE,LABEL',
                         capture=True))['blockdevices']


def descendants(node):
    yield node
    for child in node.get('children', []):
        yield from descendants(child)


def validate_disk(node):
    if node.get('type') != 'disk' or node.get('ro') or int(node['size']) < 24 * 1024**3:
        raise Error('select a writable whole disk of at least 24 GiB')
    if not re.fullmatch(r'/dev/[a-zA-Z0-9]+', node['name']):
        raise Error('unexpected disk path')
    for child in descendants(node):
        if any(child.get('mountpoints') or []):
            raise Error('disk or child is mounted/in use: ' + child['name'])
        if child.get('type') not in ('disk', 'part'):
            raise Error('disk has an active mapping: ' + child['name'])
        if str(child.get('fstype', '')).lower() in ('ntfs', 'bitlocker'):
            raise Error('Windows storage is protected')
        if str(child.get('label', '')).lower() in ('ventoy', 'vtoyefi'):
            raise Error('Ventoy media is protected')


def disk_identity(node):
    return {k: node.get(k) for k in ('name', 'size', 'model', 'serial', 'wwn', 'maj:min')}


def approval(node):
    digest = hashlib.sha256(json.dumps(disk_identity(node), sort_keys=True).encode()).hexdigest()[:12]
    return 'ERASE ' + node['name'] + ' ' + digest


def selected_disk(path):
    matches = [d for d in inventory() if d['name'] == path]
    if len(matches) != 1:
        raise Error('disk disappeared or selection is ambiguous')
    validate_disk(matches[0])
    return matches[0]


def profile(value):
    if not isinstance(value, dict) or set(value) - {'username', 'hostname', 'timezone', 'packages'}:
        raise Error('profile accepts username, hostname, timezone and packages only')
    user = value.get('username', '')
    host = value.get('hostname', '')
    zone = value.get('timezone', 'UTC')
    packages = value.get('packages', [])
    if not isinstance(user, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', user) or user == 'root':
        raise Error('invalid username')
    if not isinstance(host, str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', host):
        raise Error('invalid hostname')
    if not isinstance(zone, str) or not re.fullmatch(r'[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*', zone):
        raise Error('invalid timezone')
    if not isinstance(packages, list) or len(packages) > 256 or any(
            not isinstance(p, str) or not re.fullmatch(r'[a-zA-Z0-9@_+][a-zA-Z0-9@_.+-]*', p) for p in packages):
        raise Error('invalid native package selection')
    return {'username': user, 'hostname': host, 'timezone': zone, 'packages': sorted(set(packages))}


def partition(disk, number):
    return disk + ('p' if disk[-1].isdigit() else '') + str(number)


def write(relative, text, mode=0o644):
    path = TARGET / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    path.chmod(mode)


def chroot(*args, **kwargs):
    return run('arch-chroot', TARGET, *args, **kwargs)


def verify_payload():
    manifest = json.loads((PAYLOAD / 'packages.json').read_text())
    if set(manifest) != {'version', 'packages'} or not re.fullmatch(r'\d+\.\d+\.\d+', manifest['version']):
        raise Error('invalid engine manifest')
    packages = manifest['packages']
    if len(packages) != 2 or not all(re.fullmatch(r'frankenstein-(core|openbox)-[A-Za-z0-9_.+-]+\.pkg\.tar\.zst', n) for n in packages):
        raise Error('expected core and Openbox package artifacts')
    for name, digest in packages.items():
        with (PAYLOAD / 'packages' / name).open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                raise Error('engine package integrity check failed')
    return manifest


def install(node, config, password, luks_secret, manifest):
    # Repeat preconditions immediately before the first destructive operation.
    fresh = selected_disk(node['name'])
    if disk_identity(fresh) != disk_identity(node):
        raise Error('disk identity changed after approval')
    if TARGET.exists() and any(TARGET.iterdir()):
        raise Error('installation mount directory is not empty')
    if Path('/dev/mapper/' + MAPPER).exists():
        raise Error('installation mapper already exists')
    disk = node['name']
    esp, root = partition(disk, 1), partition(disk, 2)
    mounted = opened = False
    try:
        run('sfdisk', '--wipe', 'always', disk, secret='label: gpt\nsize=2GiB, type=U\ntype=L\n')
        run('udevadm', 'settle')
        run('mkfs.fat', '-F', '32', '-n', 'FRANKENBOOT', esp)
        run('cryptsetup', 'luksFormat', '--type', 'luks2', '--batch-mode', '--key-file', '-', root, secret=luks_secret)
        run('cryptsetup', 'open', '--key-file', '-', root, MAPPER, secret=luks_secret)
        opened = True
        run('mkfs.ext4', '-L', 'frankenstein', '/dev/mapper/' + MAPPER)
        TARGET.mkdir(parents=True, exist_ok=True)
        run('mount', '/dev/mapper/' + MAPPER, TARGET)
        mounted = True
        (TARGET / 'boot').mkdir()
        run('mount', '--mkdir', '-o', 'fmask=0077,dmask=0077', esp, TARGET / 'boot')
        cpu = Path('/proc/cpuinfo').read_text()
        microcode = ['intel-ucode'] if 'GenuineIntel' in cpu else ['amd-ucode'] if 'AuthenticAMD' in cpu else []
        run('pacstrap', '-K', TARGET, *BASE, *microcode, *config['packages'])
        write('etc/fstab', run('genfstab', '-U', TARGET, capture=True) + '\n')
        write('etc/hostname', config['hostname'] + '\n')
        write('etc/locale.gen', 'en_US.UTF-8 UTF-8\n')
        write('etc/locale.conf', 'LANG=en_US.UTF-8\n')
        write('etc/vconsole.conf', 'KEYMAP=us\n')
        chroot('ln', '-sf', '/usr/share/zoneinfo/' + config['timezone'], '/etc/localtime')
        chroot('locale-gen')
        write('etc/mkinitcpio.conf.d/frankenstein.conf',
              'HOOKS=(base systemd autodetect microcode modconf kms keyboard sd-vconsole block sd-encrypt filesystems fsck)\n')
        chroot('mkinitcpio', '-P')
        uuid = run('cryptsetup', 'luksUUID', root, capture=True)
        if not re.fullmatch(r'[a-f0-9-]{36}', uuid):
            raise Error('invalid LUKS UUID')
        chroot('bootctl', '--esp-path=/boot', '--no-variables', 'install')
        write('boot/loader/loader.conf', 'default frankenstein.conf\ntimeout 5\neditor no\n')
        for kernel, title in [('linux', 'Frankenstein'), ('linux-lts', 'Frankenstein LTS recovery')]:
            name = 'frankenstein' if kernel == 'linux' else 'frankenstein-lts'
            write('boot/loader/entries/' + name + '.conf',
                  f'title {title}\nlinux /vmlinuz-{kernel}\ninitrd /initramfs-{kernel}.img\n'
                  f'options rd.luks.name={uuid}={MAPPER} root=/dev/mapper/{MAPPER} rw\n')
        user = config['username']
        chroot('useradd', '--create-home', '--groups', 'wheel', '--shell', '/bin/bash', user)
        chroot('chpasswd', secret=user + ':' + password + '\n')
        chroot('passwd', '-l', 'root')
        write('etc/sudoers.d/10-frankenstein', '%wheel ALL=(ALL:ALL) ALL\n', 0o440)
        chroot('visudo', '-cf', '/etc/sudoers')
        staging = TARGET / 'var/tmp/frankenstein-packages'
        staging.mkdir(mode=0o700)
        for name in manifest['packages']:
            shutil.copyfile(PAYLOAD / 'packages' / name, staging / name)
        chroot('pacman', '-U', '--noconfirm', *['/var/tmp/frankenstein-packages/' + n for n in manifest['packages']])
        shutil.rmtree(staging)
        for selection in ('shell', 'openbox'):
            # Fresh useradd skeleton is deliberately superseded by the selected profile.
            chroot('runuser', '-u', user, '--', 'frankenstein', 'profile', 'apply', selection, '--replace')
        chroot('runuser', '-u', user, '--', 'frankenstein', 'profile', 'verify')
        chroot('systemctl', 'enable', 'NetworkManager.service', 'systemd-timesyncd.service',
               'fstrim.timer', 'frankenstein-first-boot.service')
        write('etc/frankenstein/install.json', json.dumps({
            'version': manifest['version'], 'username': user, 'filesystem': 'ext4',
            'encrypted': True, 'boot_verified': False}) + '\n')
        for name in ('vmlinuz-linux', 'initramfs-linux.img', 'vmlinuz-linux-lts',
                     'initramfs-linux-lts.img', 'EFI/BOOT/BOOTX64.EFI'):
            if not (TARGET / 'boot' / name).is_file():
                raise Error('missing required boot artifact: ' + name)
        chroot('pacman', '-Qk', 'frankenstein-core', 'frankenstein-openbox', 'linux', 'linux-lts')
        run('sync')
    finally:
        # Keep mappings intact if unmount fails; never close a mounted filesystem.
        if mounted:
            run('umount', '-R', TARGET)
        if opened:
            run('cryptsetup', 'close', MAPPER)


def read_secret(prompt):
    first = getpass.getpass(prompt)
    if len(first) < 12 or '\n' in first or '\r' in first or '\x00' in first:
        raise Error('secret must have at least 12 characters and no control separators')
    if first != getpass.getpass('Repeat: '):
        raise Error('secrets do not match')
    return first


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disk', help='whole disk to inspect; no default selection')
    parser.add_argument('--profile', type=Path, help='non-secret username/hostname/timezone/packages JSON')
    parser.add_argument('--execute', action='store_true', help='request installation; still requires typed approval')
    args = parser.parse_args(argv)
    if not args.disk:
        print(json.dumps(inventory(), indent=2))
        return 0
    node = selected_disk(args.disk)
    print(json.dumps(disk_identity(node), indent=2))
    if not args.execute:
        print('PLAN ONLY: GPT, 2 GiB ESP, LUKS2/ext4 root, Arch + Openbox, Linux + LTS.')
        return 0
    if not sys.stdin.isatty() or os.geteuid() != 0 or not Path('/sys/firmware/efi').is_dir():
        raise Error('execution requires root, a local interactive terminal and UEFI boot')
    if not Path('/etc/arch-release').exists() or not Path('/run/archiso').exists():
        raise Error('boot the live Arch/Frankenstein installation environment')
    for provider in ('lsblk', 'sfdisk', 'udevadm', 'mkfs.fat', 'cryptsetup', 'mkfs.ext4',
                     'mount', 'umount', 'pacstrap', 'genfstab', 'arch-chroot', 'sync'):
        if not shutil.which(provider):
            raise Error('missing provider: ' + provider)
    config = profile(json.loads(args.profile.read_text()) if args.profile else {
        'username': input('Username: '), 'hostname': input('Hostname: '),
        'timezone': input('Timezone [UTC]: ') or 'UTC'})
    if not (Path('/usr/share/zoneinfo') / config['timezone']).is_file():
        raise Error('timezone is not installed')
    manifest = verify_payload()
    # Refresh only live-media package metadata; the installed target uses pacstrap's database.
    run('pacman', '-Sy', '--noconfirm')
    run('pacman', '-Si', *BASE, *config['packages'], capture=True)
    password = read_secret('New account password: ')
    print('Keep this disk recovery passphrase outside the encrypted system. It is not a vault recovery key.')
    luks_secret = read_secret('Disk recovery passphrase: ')
    print('ALL DATA ON THE SELECTED DISK WILL BE ERASED. Type: ' + approval(node))
    if input('Approval: ') != approval(node):
        raise Error('disk erase was not approved')
    install(node, config, password, luks_secret, manifest)
    print('Installation written. Reboot, unlock the disk, log in, then run startx. Boot is not yet verified.')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Error, OSError, ValueError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        sys.exit(2)
    except (KeyboardInterrupt, EOFError):
        sys.exit(130)
