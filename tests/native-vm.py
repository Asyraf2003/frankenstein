#!/usr/bin/env python3
# VM transport adapted from MIT-licensed Blueprint experiments, Copyright (c) 2026 Asyraf.
# See licenses/upstream-MIT. Guest scenarios use only the public Frankenstein tree.
"""Opt-in public L1 proof: python3 tests/native-vm.py --state /tmp/new-proof.

Requires sudo -n docker, /dev/kvm, gpg, network and 5 GiB free in --state.
Only a new disposable disk is modified. No host home, device other than KVM,
credential, display or network namespace is exposed. Logs/disks stay in --state.
--image may reuse the exact pinned official image; its digest is always checked.
This proves reconstruction on installed Arch, not blank-disk installation,
physical hardware acceptance or atomic whole-system rollback.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'Arch-Linux-x86_64-basic-20261015.611680.qcow2'
SHA256 = 'bb888a084568f4e68b1260ffa614ebf806c79668fa20f946c691973538f4d33c'
PRIMARY = '1B9A16984A4E8CB448712D2AE0B78BF4326C6F8F'
TOOLCHAIN = 'frankenstein-l1-vm'
DOCKERFILE = '''FROM archlinux:base
RUN pacman -Syu --noconfirm --needed qemu-system-x86 qemu-img edk2-ovmf python curl gnupg
RUN pacman -Syu --noconfirm --needed qemu-hw-display-virtio-vga qemu-hw-display-virtio-gpu openssh sshpass
'''


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def docker(*args, **kwargs):
    return run('sudo', '-n', 'docker', *args, **kwargs)


def prepare(state, image):
    url = 'https://geo.mirror.pkgbuild.com/images/v20261015.611680/' + IMAGE
    if image:
        shutil.copyfile(image, state/'base.qcow2')
    else:
        urllib.request.urlretrieve(url, state/'base.qcow2')
    with (state/'base.qcow2').open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != SHA256:
            raise RuntimeError('image digest mismatch')
    urllib.request.urlretrieve(url+'.sig', state/'base.qcow2.sig')
    keytext = urllib.request.urlopen('https://raw.githubusercontent.com/archlinux/arch-boxes/master/README.md', timeout=30).read().decode()
    key = re.search(r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----', keytext, re.S).group()
    (state/'image-key.asc').write_text(key)
    (state/'gnupg').mkdir(mode=0o700)
    run('gpg', '--homedir', str(state/'gnupg'), '--batch', '--import', str(state/'image-key.asc'), capture_output=True)
    result = run('gpg', '--homedir', str(state/'gnupg'), '--batch', '--status-fd', '1', '--verify', str(state/'base.qcow2.sig'), str(state/'base.qcow2'), capture_output=True)
    if not any(line.startswith('[GNUPG:] VALIDSIG ') and line.split()[-1] == PRIMARY for line in result.stdout.splitlines()):
        raise RuntimeError('image signer mismatch')
    (state/'image-verification.txt').write_text(result.stdout+result.stderr)
    # Explicit public payload, without .git, host credentials or private sources.
    with tarfile.open(state/'source.tar', 'w') as archive:
        def public(info):
            if '__pycache__' in Path(info.name).parts or info.name.endswith('.pyc'):
                return None
            if info.issym() or info.islnk():
                raise RuntimeError('source links refused: '+info.name)
            return info
        for name in ('bootstrap', 'bin', 'lib', 'profiles', 'assets', 'tests', 'packaging', 'licenses', 'LICENSE'):
            archive.add(ROOT/name, arcname=name, filter=public)
    (state/'Dockerfile').write_text(DOCKERFILE)
    (state/'.dockerignore').write_text('*\n!Dockerfile\n')
    with (state/'image-build.log').open('w') as log:
        docker('build', '-t', TOOLCHAIN, str(state), stdout=log, stderr=subprocess.STDOUT)


class VM:
    def __init__(self, state):
        self.state = state
        self.name = 'frankenstein-proof-'+secrets.token_hex(6)
        self.running = False

    def tool(self, *args):
        return docker('run', '--rm', '--user', f'{os.getuid()}:{os.getgid()}', '--mount', f'type=bind,src={self.state},dst=/proof', TOOLCHAIN, *args, capture_output=True)

    def ssh(self, command, timeout=120, check=True):
        result = subprocess.run(['sudo', '-n', 'docker', 'exec', '--user', '0', self.name,
            'sshpass', '-p', 'arch', 'ssh', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'UserKnownHostsFile=/tmp/known_hosts', '-o', 'ConnectTimeout=3',
            '-p', '2222', 'arch@127.0.0.1', 'bash -eo pipefail -c '+shlex.quote(command)], text=True, capture_output=True, timeout=timeout)
        with (self.state/'guest.log').open('a') as log:
            log.write('$ '+command+'\n'+result.stdout+result.stderr)
        if check and result.returncode:
            raise RuntimeError(f'guest command failed ({result.returncode}): {command}\n{result.stdout[-3000:]}{result.stderr[-3000:]}')
        return result

    def wait(self, predicate, description, timeout=120):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(1)
        raise RuntimeError('timeout: '+description)

    def start(self, disk):
        for name in ('serial.sock', 'qmp.sock'):
            (self.state/name).unlink(missing_ok=True)
        docker('run', '-d', '--name', self.name, '--user', f'{os.getuid()}:{os.getgid()}',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--device', '/dev/kvm',
            '--mount', f'type=bind,src={self.state},dst=/proof', TOOLCHAIN,
            'qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '3072', '-smp', '2', '-machine', 'q35',
            '-smbios', 'type=1,product=Frankenstein-L1-Disposable', '-display', 'none', '-device', 'virtio-vga',
            '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd',
            '-drive', 'if=pflash,format=raw,file=/proof/vars.fd',
            '-drive', f'file=/proof/{disk},format=qcow2,if=virtio',
            '-netdev', 'user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22', '-device', 'virtio-net-pci,netdev=net0',
            '-virtfs', 'local,path=/proof,mount_tag=proof,security_model=none',
            '-serial', 'unix:/proof/serial.sock,server=on,wait=off', '-qmp', 'unix:/proof/qmp.sock,server=on,wait=off', capture_output=True)
        self.running = True
        self.wait(lambda: self.ssh('true', check=False, timeout=10).returncode == 0, 'SSH login')
        self.ssh("test $(cat /sys/class/dmi/id/product_name) = Frankenstein-L1-Disposable && test -d /sys/firmware/efi && sudo systemctl enable --now serial-getty@ttyS0.service")

    def serial_login(self):
        with socket.socket(socket.AF_UNIX) as sock, (self.state/'serial.log').open('a') as log:
            sock.settimeout(1)
            sock.connect(str(self.state/'serial.sock'))
            buffer = ''
            def expect(pattern):
                nonlocal buffer
                deadline = time.monotonic()+60
                while time.monotonic() < deadline:
                    match = re.search(pattern, buffer)
                    if match:
                        buffer = buffer[match.end():]
                        return
                    try:
                        data = sock.recv(65536).decode(errors='replace')
                    except socket.timeout:
                        continue
                    log.write(data); log.flush(); buffer += data
                raise RuntimeError('PAM console login timeout: '+pattern)
            sock.sendall(b'\n')
            expect(r'login: ')
            sock.sendall(b'arch\n')
            expect(r'Password: ')
            sock.sendall(b'arch\n')
            expect(r'\$ ')
            token = secrets.token_hex(8)
            # Confirm output before logout resets the emulated UART/getty.
            sock.sendall(('printf "\\n%s\\n" '+token+'\n').encode())
            expect(r'\r?\n'+token+r'\r?\n')
            sock.sendall(b'exit\n')

    def keys(self, command):
        # Only a-z and spaces needed for the local TTY login/session command.
        assert re.fullmatch('[a-z ]+', command)
        with socket.socket(socket.AF_UNIX) as sock:
            sock.settimeout(10); sock.connect(str(self.state/'qmp.sock'))
            stream = sock.makefile('rwb', buffering=0)
            json.loads(stream.readline())
            def send(payload):
                stream.write((json.dumps(payload)+'\n').encode())
                while True:
                    response = json.loads(stream.readline())
                    if 'error' in response:
                        raise RuntimeError(str(response))
                    if 'return' in response:
                        return
            send({'execute': 'qmp_capabilities'})
            for char in command+'\n':
                key = {' ': 'spc', '\n': 'ret'}.get(char, char)
                send({'execute': 'human-monitor-command', 'arguments': {'command-line': 'sendkey '+key}})
                time.sleep(.15)

    def stop(self):
        if self.running:
            docker('stop', '--time', '15', self.name, capture_output=True)
            result = docker('logs', self.name, capture_output=True)
            (self.state/'qemu.log').write_text(result.stdout+result.stderr)
            docker('rm', self.name, capture_output=True)
            self.running = False


SETUP = r'''set -euo pipefail
sudo mkdir -p /proof /build
sudo mount -t 9p -o trans=virtio,version=9p2000.L proof /proof
sudo tar -xf /proof/source.tar -C /build
sudo chown -R arch:arch /build
sudo pacman -Syu --noconfirm --needed base-devel python sudo networkmanager bluez bluez-utils xorg-xauth xdotool wmctrl xorg-xprop libpulse
cd /build
printf '\n\n\n\n' | ./bootstrap openbox
pacman -Qkk frankenstein-core frankenstein-openbox
frankenstein profile apply shell --replace
frankenstein profile apply openbox
frankenstein profile verify
sudo frankenstein service enable network
sudo frankenstein service enable bluetooth
sudo systemctl start NetworkManager
sudo systemctl enable getty@tty1.service
cat > ~/session <<'SESSION'
#!/bin/bash
set -euo pipefail
test "$XDG_SEAT" = seat0
test "$XDG_VTNR" = 1
systemctl --user is-active default.target
exec startx > ~/startx.log 2>&1
SESSION
chmod +x ~/session
sync
'''

DESKTOP = r'''set -euo pipefail
export DISPLAY=:0 XAUTHORITY=$HOME/.Xauthority
wmctrl -m | grep Openbox
xdotool key --clearmodifiers super+Return
for n in {1..30}; do xdotool search --onlyvisible --class XTerm && break; sleep 1; done
xdotool search --onlyvisible --class XTerm
xdotool key --clearmodifiers super+2
test "$(xdotool get_desktop)" = 1
xdotool key --clearmodifiers super+1
for unit in pipewire.socket pipewire-pulse.socket; do
    systemctl --user is-active "$unit"
done
for n in {1..30}; do pactl info && break; sleep 1; done
for unit in pipewire.service pipewire-pulse.service wireplumber.service; do
    systemctl --user is-active "$unit"
done
pactl load-module module-null-sink sink_name=proof_sink
pactl load-module module-remap-source master=proof_sink.monitor source_name=proof_source
node_id() {
    pw-dump | python -c 'import json,sys; print(next((n["id"] for n in json.load(sys.stdin) if n.get("info", {}).get("props", {}).get("node.name") == sys.argv[1]), ""))' "$1"
}
for name in proof_sink proof_source; do
    for n in {1..30}; do id=$(node_id "$name"); [[ -n $id ]] && break; sleep 1; done
    test -n "$id"
    wpctl set-default "$id"
done
for n in {1..30}; do vol status && mic status && break; sleep 1; done
vol 50; vol | grep 'Volume: 0.50'
mic 50; mic | grep 'Volume: 0.50'
vol mute; vol | grep MUTED; vol unmute
mic mute; mic | grep MUTED; mic unmute
openbox --exit
'''


def proof(vm):
    vm.start('installed.qcow2')
    vm.serial_login()
    print('UEFI_PAM=PASS', flush=True)
    vm.ssh('bash -c '+shlex.quote(SETUP), timeout=1800)
    print('PUBLIC_BOOTSTRAP=PASS', flush=True)
    old_boot = vm.ssh('cat /proc/sys/kernel/random/boot_id').stdout.strip()
    # A clean shutdown before cloning; never snapshot a running filesystem.
    vm.ssh('sudo systemctl poweroff', check=False)
    vm.wait(lambda: docker('inspect', '--format', '{{.State.Running}}', vm.name, capture_output=True).stdout.strip() == 'false', 'clean shutdown')
    vm.stop()
    vm.tool('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', '/proof/installed.qcow2', '/proof/reconstructed.qcow2')
    vm.start('reconstructed.qcow2')
    assert vm.ssh('cat /proc/sys/kernel/random/boot_id').stdout.strip() != old_boot
    vm.serial_login()
    print('OFFLINE_CLONE_BOOT=PASS', flush=True)
    verify_installed(vm)


def verify_installed(vm):
    vm.ssh('for unit in NetworkManager bluetooth; do test "$(systemctl is-enabled "$unit")" = enabled; done; systemctl is-active NetworkManager; test "$(systemctl show bluetooth -p ConditionResult --value)" = no; frankenstein profile verify')
    vm.keys('arch'); time.sleep(2); vm.keys('arch')
    vm.wait(lambda: 'seat0' in vm.ssh('loginctl list-sessions --no-legend', check=False).stdout, 'local PAM seat login')
    vm.keys('bash session')
    vm.wait(lambda: vm.ssh('DISPLAY=:0 XAUTHORITY=$HOME/.Xauthority wmctrl -m', check=False).returncode == 0, 'native startx')
    vm.ssh('bash -c '+shlex.quote(DESKTOP), timeout=120)
    print('TTY_DESKTOP_AUDIO=PASS', flush=True)
    vm.wait(lambda: vm.ssh('pgrep -x Xorg', check=False).returncode != 0, 'TTY logout')
    vm.ssh("printf '\\n' | frankenstein packages install tree; tree --version", timeout=300)
    vm.ssh("printf '\\n' | frankenstein packages remove tree; ! pacman -Q tree", timeout=120)
    vm.ssh("cp ~/.xinitrc ~/saved-xinitrc; printf '\\n# drift\\n' >> ~/.xinitrc; if frankenstein profile rollback; then exit 1; fi; cp ~/saved-xinitrc ~/.xinitrc; frankenstein profile rollback; test ! -e ~/.xinitrc; frankenstein profile verify; frankenstein profile apply openbox; frankenstein profile verify")
    vm.ssh('python - <<\'PY\'\n'+RECOVERY+'\nPY')
    print('PACKAGE_PROFILE_RECOVERY=PASS', flush=True)
    vm.ssh('sudo systemctl poweroff', check=False)
    vm.wait(lambda: docker('inspect', '--format', '{{.State.Running}}', vm.name, capture_output=True).stdout.strip() == 'false', 'final shutdown')


RECOVERY = '''import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
spec = importlib.util.spec_from_file_location('profiles', '/usr/lib/frankenstein/profiles.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
with tempfile.TemporaryDirectory(prefix='public-recovery-') as directory:
    home = Path(directory)
    original = b'original user shell\\n'
    (home/'.bashrc').write_bytes(original)
    manager = p.Profiles(home=home)
    manager.state.mkdir(mode=0o700, parents=True)
    save = p.save
    def fail_receipt(path, value):
        if path == manager.current:
            raise OSError('disposable receipt failure')
        return save(path, value)
    p.save = fail_receipt
    try:
        manager.apply('shell', replace=True)
    except OSError:
        pass
    else:
        raise AssertionError('receipt failure was not injected')
    finally:
        p.save = save
    assert manager.pending.exists()
    result = subprocess.run(['frankenstein', 'profile', 'recover'], env={**os.environ, 'HOME': directory}, check=True)
    assert (home/'.bashrc').read_bytes() == original
    assert not manager.pending.exists()
print('INSTALLED_PROFILE_RECOVERY=PASS')
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True, help='new evidence directory (must not exist)')
    parser.add_argument('--image', type=Path, help='optional cached official image, checked against pinned SHA256')
    args = parser.parse_args()
    if not Path('/dev/kvm').exists():
        parser.error('/dev/kvm required')
    state = args.state.absolute()
    state.mkdir(mode=0o700, parents=False, exist_ok=False)
    if shutil.disk_usage(state).free < 5*1024**3:
        parser.error('at least 5 GiB free required')
    print('EVIDENCE='+str(state), flush=True)
    prepare(state, args.image)
    vm = VM(state)
    try:
        vm.tool('cp', '/usr/share/edk2/x64/OVMF_VARS.4m.fd', '/proof/vars.fd')
        vm.tool('qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', '/proof/base.qcow2', '/proof/installed.qcow2')
        proof(vm)
        (state/'proof.json').write_text(json.dumps({'result': 'PASS', 'image': IMAGE, 'sha256': SHA256, 'source_sha256': hashlib.sha256((state/'source.tar').read_bytes()).hexdigest(), 'checks': ['UEFI', 'PAM serial and seat login', 'public bootstrap', 'offline installed-disk clone boot', 'boot services', 'user manager', 'TTY startx and logout', 'X11 shortcuts', 'PipeWire virtual audio', 'package lifecycle', 'profile drift and rollback', 'interrupted profile receipt recovery']}, indent=2)+'\n')
        print('PUBLIC_NATIVE_VM_PROOF=PASS', flush=True)
    finally:
        vm.stop()


if __name__ == '__main__':
    main()
