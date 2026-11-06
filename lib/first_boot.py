"""Verify the running base installation; do not infer USB/vault or recovery proof."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def check(*command):
    return subprocess.check_output(command, text=True).strip()


def main():
    install = json.loads(Path('/etc/frankenstein/install.json').read_text())
    root = json.loads(check('findmnt', '--json', '--output', 'SOURCE,FSTYPE', '/'))['filesystems'][0]
    if root['fstype'] != install['filesystem'] or not root['source'].startswith('/dev/mapper/'):
        raise RuntimeError('root filesystem does not match encrypted installation')
    check('cryptsetup', 'status', 'frankenstein-root')
    check('systemctl', 'is-active', 'NetworkManager.service')
    check('pacman', '-Qk', 'frankenstein-core', 'frankenstein-openbox', 'linux', 'linux-lts')
    check('runuser', '-u', install['username'], '--', 'frankenstein', 'profile', 'verify')
    for name in ('vmlinuz-linux', 'initramfs-linux.img', 'vmlinuz-linux-lts', 'initramfs-linux-lts.img'):
        if not (Path('/boot') / name).is_file():
            raise RuntimeError('missing boot artifact: ' + name)
    result = {'engine': install['version'], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
              'kernel': platform.release(), 'base_verified': True, 'recovery_boot_verified': False}
    directory = Path('/var/lib/frankenstein')
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = directory / 'boot.json.tmp'
    temporary.write_text(json.dumps(result) + '\n')
    temporary.chmod(0o644)
    os.replace(temporary, directory / 'boot.json')
    print('FRANKENSTEIN_BASE_BOOT=PASS')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print('First-boot verification failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
