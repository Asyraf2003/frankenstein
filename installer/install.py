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
import tempfile

PAYLOAD = Path('/opt/frankenstein')
TARGET = Path('/mnt/frankenstein')
MAPPER = 'frankenstein-root'
BASE = ['base', 'linux', 'linux-lts', 'linux-firmware', 'mkinitcpio', 'cryptsetup',
        'e2fsprogs', 'dosfstools', 'sudo', 'networkmanager', 'python', 'git',
        'age', 'android-tools', 'openssl', 'github-cli', 'rclone',
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


def verify_payload(manifest=None, directory=None):
    manifest = json.loads((PAYLOAD / 'packages.json').read_text()) if manifest is None else manifest
    directory = PAYLOAD / 'packages' if directory is None else Path(directory)
    if not isinstance(manifest, dict) or set(manifest) != {'version', 'packages'} or not isinstance(manifest['version'], str) or not re.fullmatch(r'\d+\.\d+\.\d+', manifest['version']):
        raise Error('invalid engine manifest')
    packages = manifest['packages']
    if not isinstance(packages, dict) or len(packages) != 2:
        raise Error('expected core and Openbox package artifacts')
    roles = set()
    for name, digest in packages.items():
        match = re.fullmatch(r'frankenstein-(core|openbox)-' + re.escape(manifest['version']) + r'-[1-9][0-9]*-any\.pkg\.tar\.zst', name)
        if not match or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise Error('package role, version or checksum is invalid')
        roles.add(match.group(1))
    if roles != {'core', 'openbox'}:
        raise Error('expected distinct core and Openbox packages')
    for name, digest in packages.items():
        artifact = directory / name
        if artifact.is_symlink() or not artifact.is_file():
            raise Error('package artifact must be a regular file')
        with artifact.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                raise Error('engine package integrity check failed')
    return manifest


def select_engine(tag, experimental, temporary, paired_credentials=None):
    if bool(tag) == bool(experimental):
        raise Error('select --engine-release vMAJOR.MINOR.PATCH, or explicitly --experimental-engine for testing')
    if experimental:
        manifest = verify_payload()
        return {**manifest, '_directory': PAYLOAD / 'packages', 'source': {'channel': 'experimental'}}
    library = PAYLOAD / 'lib' if (PAYLOAD / 'lib').is_dir() else Path(__file__).resolve().parents[1] / 'lib'
    sys.path.insert(0, str(library))
    import releases
    try:
        with releases.owner_credentials(paired_credentials):
            directory = releases.stage(tag, Path(temporary) / 'selected-engine')
        attested = releases.validate_manifest(json.loads((directory / 'engine.json').read_text()), tag)
    except releases.Error as error:
        raise Error(str(error) + '; connect or refresh GitHub on the paired phone, then retry; no experimental fallback') from None
    manifest = verify_payload({k: attested[k] for k in ('version', 'packages')}, directory)
    # Check actual native metadata, not just names on release assets.
    for name in manifest['packages']:
        expected = name.removesuffix('-any.pkg.tar.zst').rsplit('-', 2)
        if run('pacman', '-Qp', directory / name, capture=True) != expected[0] + ' ' + expected[1] + '-' + expected[2]:
            raise Error('stable package metadata differs from its attested selection')
    return {**manifest, '_directory': directory,
            'source': {'channel': 'stable', 'tag': tag, 'commit': attested['commit'], 'repository': releases.REPOSITORY}}


def install(node, config, password, luks_secret, manifest, supplied=None):
    # pacstrap preserves pre-existing directories. A caller's private umask must
    # not turn /etc or /var into root-only directories during package bootstrap.
    # Secret files/directories retain their explicit 0600/0700 provider modes.
    previous_mask = os.umask(0o022)
    try:
        return install_target(node, config, password, luks_secret, manifest, supplied)
    finally:
        os.umask(previous_mask)


def install_target(node, config, password, luks_secret, manifest, supplied=None):
    # Repeat preconditions immediately before the first destructive operation.
    if '_directory' in manifest:
        verify_payload({k: manifest[k] for k in ('version', 'packages')}, manifest['_directory'])
    if supplied:
        supplied['recheck']()
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
        # New LUKS plaintext is pseudorandom until written and can resemble an old
        # signature. Disk approval already authorizes this freshly opened mapper.
        run('mkfs.ext4', '-F', '-L', 'frankenstein', '/dev/mapper/' + MAPPER)
        TARGET.mkdir(parents=True, exist_ok=True)
        run('mount', '/dev/mapper/' + MAPPER, TARGET)
        mounted = True
        (TARGET / 'boot').mkdir()
        run('mount', '--mkdir', '-o', 'fmask=0077,dmask=0077', esp, TARGET / 'boot')
        restored = TARGET / 'var/lib/frankenstein/provisioned'
        if supplied:
            for relative in ('var', 'var/lib', 'var/lib/frankenstein'):
                (TARGET / relative).mkdir(mode=0o755, exist_ok=True)
            # The full portable payload lands on encrypted disk, never live RAM.
            supplied['restore'](restored)
        cpu = Path('/proc/cpuinfo').read_text()
        microcode = ['intel-ucode'] if 'GenuineIntel' in cpu else ['amd-ucode'] if 'AuthenticAMD' in cpu else []
        # Only an explicitly selected portable Vaultwarden owner requests its
        # runtime. The service stays stopped until this device is authorized.
        with_vault = bool(supplied and (restored / 'state/desired/vaultwarden.json').is_file())
        vault_packages = ['docker', 'docker-compose'] if with_vault else []
        run('pacstrap', '-K', TARGET, *BASE, *microcode, *config['packages'], *vault_packages)
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
        for folder in ('downloads', 'media', 'documents'):
            chroot('install', '-d', '-m', '0700', '-o', user, '-g', user, '/home/' + user + '/' + folder)
        chroot('chpasswd', secret=user + ':' + password + '\n')
        if supplied:
            private = TARGET / 'home' / user / '.local/state/frankenstein'
            private.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.rename(restored, private / 'ecosystem')
            if supplied.get('device_state'):
                device_state = private / 'usb'
                device_state.mkdir(mode=0o700)
                for source in supplied['device_state']:
                    shutil.copyfile(source, device_state / source.name)
                    (device_state / source.name).chmod(0o600)
            chroot('chown', '-R', user + ':' + user, '/home/' + user + '/.local')
        chroot('passwd', '-l', 'root')
        write('etc/sudoers.d/10-frankenstein', '%wheel ALL=(ALL:ALL) ALL\n', 0o440)
        chroot('visudo', '-cf', '/etc/sudoers')
        staging = TARGET / 'var/cache/pacman/pkg'
        staging.mkdir(mode=0o755, parents=True, exist_ok=True)
        for name in manifest['packages']:
            shutil.copyfile(Path(manifest.get('_directory', PAYLOAD / 'packages')) / name, staging / name)
            (staging / name).chmod(0o644)
        verify_payload({k: manifest[k] for k in ('version', 'packages')}, staging)
        chroot('pacman', '-U', '--noconfirm', *['/var/cache/pacman/pkg/' + n for n in manifest['packages']])
        if with_vault:
            chroot('frankenstein', 'vault-provision', 'restore',
                   '--ecosystem', '/home/' + user + '/.local/state/frankenstein/ecosystem',
                   '--output', '/var/lib/frankenstein/vault')
        for selection in ('shell', 'openbox'):
            # Fresh useradd skeleton is deliberately superseded by the selected profile.
            chroot('runuser', '-u', user, '--', 'frankenstein', 'profile', 'apply', selection, '--replace')
        chroot('runuser', '-u', user, '--', 'frankenstein', 'profile', 'verify')
        chroot('systemctl', 'enable', 'NetworkManager.service', 'systemd-timesyncd.service',
               'fstrim.timer', 'frankenstein-first-boot.service')
        write('etc/frankenstein/install.json', json.dumps({
            'version': manifest['version'], 'username': user, 'filesystem': 'ext4',
            'engine_source': manifest.get('source', {'channel': 'experimental'}),
            'encrypted': True, 'portable_state_restored': bool(supplied),
            'vaultwarden_prepared': with_vault, 'boot_verified': False}) + '\n')
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


def valid_secret(value, minimum=12):
    if not isinstance(value, str) or not minimum <= len(value) <= 4096 or any(c in value for c in '\n\r\x00'):
        raise Error(f'secret must have at least {minimum} characters and no control separators')
    return value


def read_secret(prompt, minimum=12):
    first = valid_secret(getpass.getpass(prompt), minimum)
    if first != getpass.getpass('Repeat: '):
        raise Error('secrets do not match')
    return first


def supplied_fields(entries, decode):
    config = profile(decode(entries['desired/arch.json']))
    secrets = decode(entries['credentials/arch-install.json'])
    if not isinstance(secrets, dict) or set(secrets) != {'password', 'disk_passphrase'}:
        raise Error('installation credentials require password and disk_passphrase')
    return config, valid_secret(secrets['password'], 4), valid_secret(secrets['disk_passphrase'])


def provision_input(args, temporary):
    # Only the installation adapter interprets Arch profile/credential names.
    # Core, vault and transport remain independent of this schema and any OEM.
    library = PAYLOAD / 'lib' if (PAYLOAD / 'lib').is_dir() else Path(__file__).resolve().parents[1] / 'lib'
    sys.path.insert(0, str(library))
    import provision
    names = ['desired/arch.json', 'credentials/arch-install.json']
    if args.phone:
        state = provision.kit.outside_git(args.device_state)
        run(sys.executable, provision.usb.__file__, '--serial', args.phone, '--state', state, 'pair')
        connection = provision.connection('adb', args.phone, state)
        selected, entries = provision.selected_entries(connection, names)
        pin = state / ('phone-' + hashlib.sha256(args.phone.encode()).hexdigest() + '.der')
        supplied = {
            'recheck': lambda: provision.selected_entries(connection, [], expected=selected),
            'restore': lambda destination: provision.receive('adb', args.phone, state, destination, expected=selected),
            'device_state': [provision.kit.safe(state / name) for name in ('device.key', 'device.pem')] + [pin],
            'github_credentials': lambda: provision.selected_entries(connection, ['credentials/github.json'],
                expected=selected)[1]['credentials/github.json'],
        }
    else:
        bundle = provision.kit.outside_git(args.provisioning_bundle)
        if bundle.stat().st_size > 64 * 1024**2:
            raise Error('offline bootstrap is limited to 64 MiB; use --phone to stream a larger vault onto encrypted disk')
        prepared = Path(temporary) / 'prepared'
        provision.portable.restore(bundle, prepared, args.sha256)
        entries = {}
        for name in names:
            path = provision.kit.safe(prepared / 'state' / name)
            if path.stat().st_size > 1024**2:
                raise Error('installation profile exceeds limit')
            entries[name] = path.read_bytes()
        def recheck():
            if provision.kit.sha(bundle) != args.sha256:
                raise Error('selected provisioning bundle changed')
        supplied = {'recheck': recheck,
                    'restore': lambda destination: provision.portable.restore(bundle, destination, args.sha256),
                    'github_credentials': lambda: provision.kit.safe(prepared / 'state/credentials/github.json').read_bytes()}
    return (*supplied_fields(entries, provision.kit.decode), supplied)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disk', help='whole disk to inspect; no default selection')
    parser.add_argument('--profile', type=Path, help='non-secret username/hostname/timezone/packages JSON')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--phone', help='USB phone serial; requires owner pairing approval')
    source.add_argument('--provisioning-bundle', type=Path, help='private FPE bundle (offline bootstrap, at most 64 MiB)')
    parser.add_argument('--sha256', help='selected offline provisioning bundle digest')
    parser.add_argument('--device-state', type=Path, default=Path('/root/.local/state/frankenstein/usb'))
    parser.add_argument('--execute', action='store_true', help='request installation; still requires typed approval')
    engine = parser.add_mutually_exclusive_group()
    engine.add_argument('--engine-release', help='exact stable vMAJOR.MINOR.PATCH release to verify and install')
    engine.add_argument('--experimental-engine', action='store_true', help='explicitly install the embedded development packages for testing')
    args = parser.parse_args(argv)
    if args.profile and (args.phone or args.provisioning_bundle):
        parser.error('--profile cannot override provisioned identity')
    if bool(args.provisioning_bundle) != bool(args.sha256):
        parser.error('--provisioning-bundle requires --sha256, and vice versa')
    if not args.disk:
        print(json.dumps(inventory(), indent=2))
        return 0
    node = selected_disk(args.disk)
    print(json.dumps(disk_identity(node), indent=2))
    if not args.execute:
        print('PLAN ONLY: GPT, 2 GiB ESP, LUKS2/ext4 root, Arch + Openbox, Linux + LTS.')
        return 0
    if not args.engine_release and not args.experimental_engine:
        parser.error('installation requires --engine-release vMAJOR.MINOR.PATCH or explicit --experimental-engine')
    if not sys.stdin.isatty() or os.geteuid() != 0 or not Path('/sys/firmware/efi').is_dir():
        raise Error('execution requires root, a local interactive terminal and UEFI boot')
    if not Path('/etc/arch-release').exists() or not Path('/run/archiso').exists():
        raise Error('boot the live Arch/Frankenstein installation environment')
    for provider in ('lsblk', 'sfdisk', 'udevadm', 'mkfs.fat', 'cryptsetup', 'mkfs.ext4',
                     'mount', 'umount', 'pacstrap', 'genfstab', 'arch-chroot', 'sync'):
        if not shutil.which(provider):
            raise Error('missing provider: ' + provider)
    with tempfile.TemporaryDirectory(prefix='frankenstein-install-') as temporary:
        return execute(args, node, temporary)


def execute(args, node, temporary):
    # Paired account access must be available before stable release verification.
    # Neither pairing nor release selection writes to the installation target.
    supplied = None
    if args.phone or args.provisioning_bundle:
        config, password, luks_secret, supplied = provision_input(args, temporary)
    manifest = select_engine(args.engine_release, args.experimental_engine, temporary,
                             supplied.get('github_credentials') if supplied else None)
    if not supplied:
        config = profile(json.loads(args.profile.read_text()) if args.profile else {
            'username': input('Username: '), 'hostname': input('Hostname: '),
            'timezone': input('Timezone [UTC]: ') or 'UTC'})
    if not (Path('/usr/share/zoneinfo') / config['timezone']).is_file():
        raise Error('timezone is not installed')
    # Refresh only live-media package metadata; the installed target uses pacstrap's database.
    run('pacman', '-Sy', '--noconfirm')
    run('pacman', '-Si', *BASE, *config['packages'], capture=True)
    if not supplied:
        password = read_secret('New account password (4+ characters): ', 4)
        print('Keep this disk recovery passphrase outside the encrypted system. It is not a vault recovery key.')
        luks_secret = read_secret('Disk recovery passphrase: ')
    else:
        print('Provisioned account and disk unlock material verified. Keep a paired device key or configured recovery backup.')
    print('Install user ' + config['username'] + ' on host ' + config['hostname'] + '.')
    print('ALL DATA ON THE SELECTED DISK WILL BE ERASED. Type: ' + approval(node))
    if input('Approval: ') != approval(node):
        raise Error('disk erase was not approved')
    install(node, config, password, luks_secret, manifest, supplied)
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
