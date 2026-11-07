"""Reconcile private ecosystem state with an owner-approved USB phone."""
import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid

import provision
from provision import kit, portable, usb
import recovery_opening as opening

EMPTY = '0' * 64


def digest(value):
    return hashlib.sha256(kit.encoded(value)).hexdigest()


def inventory(root):
    """Detect ordinary concurrent edits, including identity/context/recovery changes."""
    if not root.exists():
        return None
    kit.safe(root)
    kit.require(root.is_dir(), 'SYNC_INVALID_PC_DIRECTORY')
    result = {}
    for path in [root, *sorted(root.rglob('*'))]:
        kit.safe(path)
        info = path.stat()
        kit.require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'SYNC_INVALID_FILE')
        result[path.relative_to(root).as_posix()] = [list(kit.stable(info)), kit.sha(path) if path.is_file() else None]
    return digest(result)


def summary(root):
    context = kit.context(kit.decode((root / 'context.json').read_bytes()))
    proof = kit.inspect(root / 'vault.age', root / 'identity.txt', context)['manifest']
    recipient = opening.native(['age-keygen', '-y', str(root / 'identity.txt')]).decode().strip()
    capsule = root / 'recovery'
    recovery = kit.sha(capsule / 'manifest.json') if capsule.exists() else None
    if recovery:
        opening.inspect(capsule, recovery)
    return {'kit_id': proof['kit_id'], 'updated_at': proof['created_at'], 'files': proof['files'],
            'context': context, 'recipient': recipient, 'recovery': recovery}


def comparable(value):
    return {k: v for k, v in value.items() if k != 'updated_at'} if value else None


def snapshot(root, work):
    """Capture named owner state, preserving the ecosystem identity when repacking."""
    before = inventory(root)
    if before is None:
        return None, None, before
    base = summary(root)  # Invalid existing state is never treated as empty.
    kit.inventory(root / 'state')
    copied = work / 'pc-source'
    shutil.copytree(root, copied)
    kit.require(inventory(root) == before, 'SYNC_PC_CHANGED')
    (copied / 'identity.txt').chmod(0o600)
    bundle = work / 'pc.fpe'
    portable.create(copied / 'state', copied / 'identity.txt', base['context'],
                    copied / 'recovery' if base['recovery'] else None, base['recovery'], bundle,
                    kit_id=base['kit_id'])
    ready = work / 'pc-ready'
    portable.restore(bundle, ready, kit.sha(bundle))
    value = summary(ready)
    if comparable(value) == comparable(base):
        value['updated_at'] = base['updated_at']
    else:
        # File mtimes are informational only; they never decide the winner.
        value['updated_at'] = datetime.fromtimestamp(max(
            (p.stat().st_mtime for p in (copied / 'state').rglob('*') if p.is_file()),
            default=(copied / 'state').stat().st_mtime), timezone.utc).isoformat()
    return value, bundle, before


def plan(pc, phone, selected, local_version):
    if pc is None and phone is None:
        action = 'setup-phone'
    elif pc is None:
        action = 'receive-pc'
    elif phone is None:
        action = 'send-phone'
    elif comparable(pc) == comparable(phone):
        action = 'unchanged'
    else:
        action = 'conflict'
    differences = []
    if pc and phone:
        for name in sorted(set(pc['files']) | set(phone['files'])):
            if pc['files'].get(name) != phone['files'].get(name):
                differences.append(name)
        for name in ('kit_id', 'context', 'recipient', 'recovery'):
            if pc[name] != phone[name]:
                differences.append('@' + name)
    result = {'action': action, 'pc_updated_at': pc['updated_at'] if pc else None,
              'phone_updated_at': phone['updated_at'] if phone else None, 'differences': differences,
              'phone_generation': selected, 'pc_version': local_version}
    result['decision'] = digest({'plan': result, 'pc': comparable(pc), 'phone': comparable(phone)})
    return result


def exchange(ready, current):
    """Atomic Linux directory exchange; old bytes stay in the retained generation."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    kit.require(rename is not None, 'SYNC_ATOMIC_EXCHANGE_UNAVAILABLE')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(ready), -100, os.fsencode(current), 2):
        raise OSError(ctypes.get_errno(), 'atomic state exchange failed')
    kit.sync_directory(ready.parent)
    kit.sync_directory(current.parent)


def record(history, result, phase, retained=None):
    event = {**result, 'phase': phase, 'at': datetime.now(timezone.utc).isoformat(), 'retained': retained}
    path = kit.safe(history / 'updates.jsonl')
    with path.open('ab') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(kit.encoded(event))
        stream.flush()
        os.fsync(stream.fileno())
    kit.sync_directory(history)


def reconcile(root, peer, *, decide=None, preview=False, expected_plan=None):
    root = kit.outside_git(root)
    kit.private_directories(root.parent)
    history = kit.safe(root.parent / ('.' + root.name + '-sync'))
    # Separate lock/history survives replacement of the selected ecosystem.
    with kit.writer(history), tempfile.TemporaryDirectory(prefix='.device-sync-', dir=root.parent) as temporary:
        work = Path(temporary)
        pc, bundle, local_version = snapshot(root, work)
        selected = peer.current()
        phone = None
        if selected != EMPTY:
            received = work / 'phone.fpe'
            peer.pull(selected, received)
            portable.restore(received, work / 'phone', selected)
            phone = summary(work / 'phone')
        kit.require(peer.current() == selected, 'SYNC_PHONE_CHANGED')
        kit.require(inventory(root) == local_version, 'SYNC_PC_CHANGED')
        result = plan(pc, phone, selected, local_version)
        kit.require(expected_plan is None or expected_plan == result['decision'], 'SYNC_DECISION_STALE')
        if preview:
            return result
        if result['action'] == 'conflict':
            direction = decide(result) if decide else None
            if direction not in ('pc', 'phone'):
                record(history, result, 'decision-required')
                return result
            result['action'] = 'send-phone' if direction == 'pc' else 'receive-pc'
        kit.require(inventory(root) == local_version, 'SYNC_PC_CHANGED')
        kit.require(peer.current() == selected, 'SYNC_PHONE_CHANGED')
        if result['action'] == 'send-phone':
            new_id = peer.push(bundle)
            kit.require(new_id == kit.sha(bundle), 'SYNC_UPLOAD_CHANGED')
            kit.require(inventory(root) == local_version, 'SYNC_PC_CHANGED')
            record(history, result, 'activating', selected)
            peer.activate(new_id, selected)  # Receiver verifies and compare-and-swaps.
            result['new_phone_generation'] = new_id
        elif result['action'] == 'receive-pc':
            if root.exists():
                retained = history / ('generation-' + uuid.uuid4().hex)
                kit.publish_directory(work / 'phone', retained)
                record(history, result, 'exchanging', retained.name)
                kit.require(inventory(root) == local_version, 'SYNC_PC_CHANGED')
                kit.require(peer.current() == selected, 'SYNC_PHONE_CHANGED')
                exchange(retained, root)
                result['retained_pc'] = str(retained)
            else:
                kit.publish_directory(work / 'phone', root)
        record(history, result, 'complete')
        return result


class Peer:
    def __init__(self, connection):
        self.device, self.key, self.cert, self.phone = connection
        self.port = self.device.forward()

    def call(self, function, *args):
        with usb.connect(self.port, self.key, self.cert, self.phone) as stream:
            return function(stream, *args)

    def current(self):
        return self.call(usb.current)

    def pull(self, selected, destination):
        return self.call(usb.pull, selected, destination)

    def push(self, source):
        return self.call(usb.push, source)

    def activate(self, selected, previous):
        return self.call(usb.activate, selected, previous)

    def close(self):
        self.device.remove(self.port)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial', help='USB device; automatic selection requires exactly one connected phone')
    parser.add_argument('--state', type=Path, default=Path.home() / '.local/state/frankenstein/usb', help='private USB pairing identity directory')
    parser.add_argument('--ecosystem', type=Path, default=Path.home() / '.local/state/frankenstein/ecosystem')
    parser.add_argument('--openssl', default='openssl')
    parser.add_argument('--app', default=usb.APP)
    parser.add_argument('--preview', action='store_true')
    parser.add_argument('--accept-plan', help='exact decision digest from a preview')
    parser.add_argument('--use', choices=('pc', 'phone'), help='explicit conflict winner, requires --accept-plan')
    parser.add_argument('--watch', action='store_true', help='sync once on USB connection; conflicts remain pending for your choice')
    args = parser.parse_args(argv)
    if bool(args.accept_plan) != bool(args.use):
        parser.error('--accept-plan and --use are required together')
    if args.watch:
        if args.accept_plan or args.preview:
            parser.error('--watch cannot reuse an approval or preview')
        seen = None
        while True:
            try:
                devices = connected(args.adb)
                serial = args.serial if args.serial in devices else (devices[0] if not args.serial and len(devices) == 1 else None)
                if serial != seen:
                    seen = serial
                    if serial:
                        selected = argparse.Namespace(**vars(args))
                        selected.serial = serial
                        run(selected)
            except (OSError, subprocess.SubprocessError):
                seen = None
            time.sleep(3)
    if not args.serial:
        devices = connected(args.adb)
        if len(devices) != 1:
            parser.error('connect exactly one USB phone or select --serial')
        args.serial = devices[0]
    return run(args)


def connected(adb):
    result = subprocess.check_output([adb, 'devices', '-l'], text=True, stderr=subprocess.PIPE, timeout=10)
    return [parts[0] for line in result.splitlines() if len(parts := line.split()) > 2
            and parts[1] == 'device' and any(p.startswith('usb:') for p in parts[2:])]


def notify(message):
    if shutil.which('notify-send'):
        try:
            subprocess.run(['notify-send', '--app-name=Frankenstein', 'Frankenstein USB sync', message],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            pass  # A desktop notification failure cannot undo a committed transfer.


def run(args):

    def choose(result):
        if args.watch:
            return None
        print(json.dumps(result, indent=2), flush=True)
        if args.accept_plan:
            kit.require(args.accept_plan == result['decision'], 'SYNC_DECISION_STALE')
            return args.use
        if not sys.stdin.isatty():
            return None
        print('Both devices differ. Dates do not choose a winner. Previous copies are retained.')
        return input('Use pc, phone, or Enter to leave both unchanged: ').strip().lower()

    peer = None
    try:
        # Reuse the same explicit first-pair approval and pin verification.
        key, cert = usb.identity(args.state, args.openssl)
        device = usb.USB(args.adb, args.serial, args.app)
        usb.pair(device, key, cert, args.state, args.serial)
        peer = Peer(provision.connection(args.adb, args.serial, args.state, args.openssl, args.app))
        result = reconcile(args.ecosystem, peer, decide=choose, preview=args.preview, expected_plan=args.accept_plan)
        if args.watch:
            print('SYNC=' + result['action'], flush=True)
            if result['action'] == 'conflict':
                notify('PC and phone differ. Run frankenstein sync --preview to inspect dates and changes, then sync to choose a copy.')
            elif result['action'] in ('send-phone', 'receive-pc'):
                notify('Encrypted device state synchronized. Previous versions are retained.')
        else:
            print(json.dumps(result, indent=2))
        if result['action'] == 'setup-phone' and not args.preview:
            device.run('shell', 'am', 'start', '-n', args.app + '/org.frankenstein.companion.MainActivity',
                       '--ez', 'setup_if_empty', 'true')
            print('Both devices are empty. Choose Set up this phone, then run sync again.')
        return 3 if result['action'] == 'conflict' else 0
    except (ValueError, OSError, EOFError) as error:
        print('SYNC=FAIL (' + (str(error) if isinstance(error, kit.KitError) else type(error).__name__) + ')', file=sys.stderr)
        return 1
    finally:
        if peer:
            peer.close()


if __name__ == '__main__':
    raise SystemExit(main())
