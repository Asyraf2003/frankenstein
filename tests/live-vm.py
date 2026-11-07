#!/usr/bin/env python3
"""Actual clean-disk ISO installation test. Only creates disks under a NEW directory.

Requires Linux, qemu-system-x86_64, qemu-img, OVMF and python-pexpect.
Never attaches a physical disk. Uses 4 GiB RAM. Test credentials are disposable.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import time

import pexpect

SECRET = 'frankensteintestonly'
ACCOUNT_SECRET = '1234'


class VM:
    def __init__(self, state, code, variables):
        self.state = state
        self.code = code
        shutil.copyfile(variables, state / 'vars.fd')
        subprocess.run(['qemu-img', 'create', '-f', 'qcow2', str(state / 'disk.qcow2'), '32G'], check=True)
        self.child = None
        self.log = None

    def start(self, iso=None):
        socket_path = self.state / 'qmp.sock'
        socket_path.unlink(missing_ok=True)
        args = ['-machine', 'q35', '-accel', 'kvm' if os.access('/dev/kvm', os.R_OK | os.W_OK) else 'tcg',
                '-m', '4096', '-smp', '2', '-display', 'none', '-device', 'virtio-vga',
                '-drive', f'if=pflash,format=raw,readonly=on,file={self.code}',
                '-drive', f'if=pflash,format=raw,file={self.state / "vars.fd"}',
                '-drive', f'file={self.state / "disk.qcow2"},format=qcow2,if=virtio',
                '-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0',
                '-serial', 'stdio', '-monitor', 'none',
                '-qmp', f'unix:{socket_path},server=on,wait=off', '-no-reboot']
        if iso:
            args += ['-cdrom', str(iso), '-boot', 'order=d']
        self.log = (self.state / ('live.log' if iso else 'installed.log')).open('a')
        self.child = pexpect.spawn('qemu-system-x86_64', args, encoding='utf-8', codec_errors='replace', timeout=300)
        self.child.logfile_read = self.log

    def command(self, command, timeout=120):
        token = secrets.token_hex(12)
        self.child.sendline(command + "; printf '\\n" + token + ":%s\\n' \"$?\"")
        # Guest CRLF can pass through a host PTY as CRCRLF.
        self.child.expect(token + r':(\d+)\r*\n', timeout=timeout)
        if self.child.match.group(1) != '0':
            raise RuntimeError('guest command failed: ' + command)

    def qmp(self, command, arguments):
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(20)
            sock.connect(str(self.state / 'qmp.sock'))
            stream = sock.makefile('rwb', buffering=0)
            json.loads(stream.readline())
            for payload in ({'execute': 'qmp_capabilities'}, {'execute': command, 'arguments': arguments}):
                stream.write((json.dumps(payload) + '\n').encode())
                while True:
                    result = json.loads(stream.readline())
                    if 'error' in result:
                        raise RuntimeError(str(result['error']))
                    if 'return' in result:
                        break

    def keys(self, line):
        assert re.fullmatch('[a-z ]+', line)
        for char in line + '\n':
            key = {' ': 'spc', '\n': 'ret'}.get(char, char)
            self.qmp('human-monitor-command', {'command-line': 'sendkey ' + key})
            time.sleep(.15)

    def stop(self):
        if self.child:
            self.child.close(force=True)
            self.child = None
        if self.log:
            self.log.close()
            self.log = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--firmware-code', type=Path, default=Path('/usr/share/OVMF/OVMF_CODE_4M.fd'))
    parser.add_argument('--firmware-vars', type=Path, default=Path('/usr/share/OVMF/OVMF_VARS_4M.fd'))
    args = parser.parse_args()
    iso = args.iso.resolve(strict=True)
    if not iso.is_file():
        parser.error('ISO must be a regular file')
    state = args.state.absolute()
    state.mkdir(mode=0o700, exist_ok=False)
    if shutil.disk_usage(state).free < 12 * 1024**3:
        parser.error('12 GiB free space required')
    vm = VM(state, args.firmware_code.resolve(strict=True), args.firmware_vars.resolve(strict=True))
    try:
        vm.start(iso)
        vm.child.expect(r'login:')
        vm.child.sendline('root')
        vm.child.expect(r'# ')
        vm.child.sendline('exec bash --noprofile --norc')
        vm.child.expect(r'bash-[^\r\n]*# ')
        vm.command('test -d /sys/firmware/efi && test -d /run/archiso')
        spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('provisioning-fixture.py'))
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        bundle = state / 'synthetic-install.fpe'
        selected = fixture.create(bundle, SECRET, recovery=False, account_password=ACCOUNT_SECRET)
        encoded = base64.b64encode(bundle.read_bytes()).decode()
        vm.command('umask 077; : > /root/provision.b64')
        # Keep each serial terminal line below the canonical input limit.
        for start in range(0, len(encoded), 1024):
            vm.command("printf '%s' '" + encoded[start:start + 1024] + "' >> /root/provision.b64")
        vm.command('base64 -d /root/provision.b64 > /root/provision.fpe && rm /root/provision.b64')
        vm.child.sendline('frankenstein-install --disk /dev/vda --provisioning-bundle /root/provision.fpe --sha256 ' + selected + ' --execute')
        # Account/disk credentials come from the verified synthetic vault. Only
        # this disposable disk's explicit destructive approval is automated.
        vm.child.expect(r'ERASE /dev/vda [a-f0-9]{12}')
        approval = vm.child.match.group(0)
        vm.child.expect_exact('Approval:')
        vm.child.sendline(approval)
        vm.child.expect_exact('Installation written.', timeout=1800)
        vm.child.expect(r'# ')
        # Add serial console to this disposable installation only, for independent boot proof.
        vm.child.sendline('cryptsetup open /dev/vda2 proofroot')
        vm.child.expect(r'passphrase.*:')
        vm.child.sendline(SECRET)
        vm.child.expect(r'# ')
        vm.command('mkdir -p /mnt/proof && mount /dev/mapper/proofroot /mnt/proof && mount /dev/vda1 /mnt/proof/boot')
        vm.command("sed -i '/^options /s/$/ console=tty0 console=ttyS0,115200n8/' /mnt/proof/boot/loader/entries/*.conf")
        vm.command('systemctl --root=/mnt/proof enable serial-getty@ttyS0.service')
        vm.command('umount -R /mnt/proof && cryptsetup close proofroot && sync')
        vm.child.sendline('poweroff')
        vm.child.expect(pexpect.EOF, timeout=120)
        vm.stop()
        vm.start()
        vm.child.expect(r'(?i)passphrase.*:', timeout=300)
        vm.child.sendline(SECRET)
        vm.child.expect(r'login:', timeout=300)
        vm.child.sendline('proof')
        vm.child.expect_exact('Password:')
        vm.child.sendline(ACCOUNT_SECRET)
        vm.child.expect(r'\$ ')
        vm.command('systemctl is-active frankenstein-first-boot.service && frankenstein profile verify')
        vm.command('test -r /etc/passwd && test -r /etc/profile && test -x /var/lib && id -un | grep -qx proof')
        vm.command("test -r ~/.local/state/frankenstein/ecosystem/identity.txt && test \"$(stat -c %a ~/.local/state/frankenstein/ecosystem/identity.txt)\" = 600")
        vm.command("grep -qx '{\"fixture\":\"portable-tuning-preserved\"}' ~/.local/state/frankenstein/ecosystem/state/desired/tuning.json")
        vm.command('frankenstein vault inspect --candidate ~/.local/state/frankenstein/ecosystem/vault.age --identity ~/.local/state/frankenstein/ecosystem/identity.txt --context ~/.local/state/frankenstein/ecosystem/context.json')
        vm.keys('proof')
        time.sleep(2)
        vm.keys(ACCOUNT_SECRET)
        time.sleep(3)
        vm.keys('startx')
        # A real seat/VT Xorg session, not Xvfb and not a simulated display.
        vm.command("for i in $(seq 1 60); do DISPLAY=:0 XAUTHORITY=$HOME/.Xauthority wmctrl -m 2>/dev/null | grep -q Openbox && break; sleep 1; done; DISPLAY=:0 XAUTHORITY=$HOME/.Xauthority wmctrl -m | grep Openbox", timeout=90)
        vm.command('DISPLAY=:0 XAUTHORITY=$HOME/.Xauthority frankenstein-welcome </dev/null')
        vm.qmp('screendump', {'filename': str(state / 'welcome.ppm')})
        # Exercise the separately installed recovery kernel, rather than treating
        # the existence of its boot files as proof of a working recovery path.
        # Split the marker in the shell command so command echo cannot match it.
        vm.child.sendline("sudo -k -p 'RECOVERY_''SUDO:' sh -ec \"sed -i 's/^default .*/default frankenstein-lts.conf/' /boot/loader/loader.conf; grep -qx 'default frankenstein-lts.conf' /boot/loader/loader.conf; sync; systemctl poweroff\"")
        vm.child.expect_exact('RECOVERY_SUDO:')
        vm.child.sendline(ACCOUNT_SECRET)
        vm.child.expect(pexpect.EOF, timeout=120)
        vm.stop()
        vm.start()
        vm.child.expect(r'(?i)passphrase.*:', timeout=300)
        vm.child.sendline(SECRET)
        vm.child.expect(r'login:', timeout=300)
        vm.child.sendline('proof')
        vm.child.expect_exact('Password:')
        vm.child.sendline(ACCOUNT_SECRET)
        vm.child.expect(r'\$ ')
        vm.command("uname -r | grep -E -- '-lts$'")
        vm.command('systemctl is-active frankenstein-first-boot.service && frankenstein profile verify')
        with iso.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        (state / 'proof.json').write_text(json.dumps({'result': 'PASS', 'iso_sha256': digest,
            'memory_mib': 4096, 'checks': ['live UEFI boot', 'blank disk install', 'LUKS unlock',
            'installed boot without ISO', 'PAM login', 'first-boot verification', 'TTY startx', 'Welcome',
            'LTS recovery boot', 'LTS LUKS unlock and PAM login', 'LTS first-boot verification'],
            'provisioning': ['synthetic encrypted bundle supplies account and disk credentials',
                             'four-character numeric login/sudo password', 'optional recovery skipped; surviving device key opens vault',
                             'private tuning retained', 'portable vault independently opens after boot'],
            'not_verified': ['physical hardware', 'USB pairing inside VM', 'generation rollback']}, indent=2) + '\n')
        print('CLEAN_DISK_VM_PROOF=PASS')
    except Exception:
        if vm.log:
            vm.log.flush()
        for path in state.glob('*.log'):
            print(path.name + '\n' + path.read_text(errors='replace')[-16000:])
        raise
    finally:
        vm.stop()


if __name__ == '__main__':
    main()
