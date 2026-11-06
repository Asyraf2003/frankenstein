"""Native age/Python/Go compatibility and fresh-device provisioning, synthetic only."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vault'))
import portable
import recovery_kit as kit
import recovery_opening as opening
sys.path.insert(0, str(ROOT / 'lib'))
import provision
spec = importlib.util.spec_from_file_location('native_opening', ROOT / 'tests/native-vault-opening.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
BRIDGE = Path(os.environ.get('FRANKENSTEIN_NATIVE', ROOT / 'vault/native/out/bridge'))


class Portable(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='portable-proof-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.capsule = cls.root / 'capsule'
        secret = secrets.token_urlsafe(24)
        code, _, supplied = helper.tty([ROOT / 'vault/recovery_opening.py', 'enroll', '--opening', cls.capsule], [secret] * 3)
        assert code == 0 and supplied == 3, 'native capsule enrollment failed; transcript withheld'
        cls.expected = kit.sha(cls.capsule / 'manifest.json')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(temporary.cleanup)
        self.case = Path(temporary.name)
        self.key = self.case / 'device.key'
        subprocess.run(['age-keygen', '-o', str(self.key)], check=True, capture_output=True)
        self.key.chmod(0o600)
        self.staging = self.case / 'state'
        (self.staging / 'desired').mkdir(parents=True)
        self.plain = b'{"username":"fixture","desktop":"openbox"}\n'
        (self.staging / 'desired/profile.json').write_bytes(self.plain)
        self.context = {'revisions': {'engine': '1' * 40, 'state': '2' * 40},
                        'features': ['fixture'], 'required_owners': ['desired']}
        self.bundle = self.case / 'portable.fpe'
        self.digest = portable.create(self.staging, self.key, self.context, self.capsule, self.expected, self.bundle)

    def native(self, bundle=None, selected=None):
        with (bundle or self.bundle).open('rb') as source:
            result = subprocess.run([str(BRIDGE), *(['read', selected] if selected else ['verify'])],
                                    stdin=source, capture_output=True, timeout=30)
        self.assertNotIn(b'AGE-SECRET-KEY-', result.stdout)
        self.assertNotIn(b'AGE-SECRET-KEY-', result.stderr)
        return result

    def changed(self, change_header=None, change_archive=None):
        raw = self.bundle.read_bytes()
        size = struct.unpack('>I', raw[4:8])[0]
        header = json.loads(raw[8:8 + size])
        archive = raw[8 + size:]
        if change_archive:
            archive = change_archive(archive)
            header['archive_sha256'] = hashlib.sha256(archive).hexdigest()
        if change_header:
            change_header(header)
        encoded = kit.encoded(header)
        target = self.case / ('changed-' + secrets.token_hex(4))
        target.write_bytes(b'FPE1' + struct.pack('>I', len(encoded)) + encoded + archive)
        return target

    def rejected(self, path):
        result = self.native(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'', 'native adapter exposed unverified output')
        destination = self.case / ('rejected-' + secrets.token_hex(4))
        with self.assertRaises((ValueError, OSError)):
            portable.restore(path, destination, kit.sha(path))
        self.assertFalse(destination.exists())

    def test_python_producer_native_android_consumer(self):
        result = self.native(selected='desired/profile.json')
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        value = json.loads(result.stdout)
        self.assertEqual(base64.b64decode(value['selected']['base64']), self.plain)
        self.assertEqual(value['manifest']['context'], self.context)

    def test_fresh_device_can_replicate_without_original_identity(self):
        self.key.unlink()
        shutil.rmtree(self.staging)
        restored = self.case / 'new-pc'
        portable.restore(self.bundle, restored, self.digest)
        self.assertEqual((restored / 'state/desired/profile.json').read_bytes(), self.plain)
        replicated = self.case / 'next-phone.fpe'
        portable.create(restored / 'state', restored / 'identity.txt', self.context,
                        restored / 'recovery', self.expected, replicated)
        self.assertEqual(self.native(replicated).returncode, 0)
        last = self.case / 'next-pc'
        portable.restore(replicated, last, kit.sha(replicated))
        self.assertEqual((last / 'state/desired/profile.json').read_bytes(), self.plain)

    def test_final_age_authentication_gates_all_output(self):
        self.rejected(self.changed(change_archive=lambda value: value[:-1]))

    def test_context_and_recovery_binding_are_enforced(self):
        self.rejected(self.changed(change_header=lambda header: header['context']['features'].append('wrong')))
        self.rejected(self.changed(change_header=lambda header: header.update(recovery_manifest_sha256='0' * 64)))

    def test_duplicate_json_header_is_not_ambiguous(self):
        raw = self.bundle.read_bytes()
        size = struct.unpack('>I', raw[4:8])[0]
        header = b'{"schema":1,' + raw[9:8 + size]
        target = self.case / 'duplicate.fpe'
        target.write_bytes(b'FPE1' + struct.pack('>I', len(header)) + header + raw[8 + size:])
        self.rejected(target)

    def test_tar_payload_tampering_is_rejected_even_with_valid_age(self):
        recipient = opening.native(['age-keygen', '-y', str(self.key)]).decode().strip()
        def altered(ciphertext):
            plain = subprocess.run(['age', '-d', '-i', str(self.key)], input=ciphertext,
                                   check=True, capture_output=True).stdout
            output = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(plain)) as source, tarfile.open(fileobj=output, mode='w') as target:
                for member in source.getmembers():
                    content = source.extractfile(member).read()
                    if member.name == 'payload/desired/profile.json':
                        content = b'x' * len(content)
                    target.addfile(member, io.BytesIO(content))
            return subprocess.run(['age', '-r', recipient], input=output.getvalue(), check=True, capture_output=True).stdout
        self.rejected(self.changed(change_archive=altered))

    def test_existing_destination_and_git_outputs_are_preserved(self):
        existing = self.case / 'existing'
        existing.mkdir()
        (existing / 'unrelated').write_text('preserve')
        with self.assertRaisesRegex(kit.KitError, 'OUTPUT_EXISTS'):
            portable.restore(self.bundle, existing, self.digest)
        self.assertEqual((existing / 'unrelated').read_text(), 'preserve')
        repo = self.case / 'repo'
        repo.mkdir()
        (repo / '.git').write_text('gitdir: C:/foreign/worktree\n')
        with self.assertRaisesRegex(kit.KitError, 'OUTSIDE_GIT'):
            portable.restore(self.bundle, repo / 'restore', self.digest)

    def test_provision_receives_selected_generation_and_fails_closed(self):
        # A local wire-protocol fixture, not evidence of Android/TLS pairing.
        # The real receive, hashing, age decrypt and atomic restore all execute.
        for fault in (None, 'changed', 'disconnect', 'corrupt', 'empty'):
            with self.subTest(fault=fault):
                state = self.case / ('transport-' + str(fault))
                state.mkdir(mode=0o700)
                serial = 'fixture'
                (state / ('phone-' + hashlib.sha256(serial.encode()).hexdigest() + '.der')).write_bytes(b'fixture')
                output = self.case / ('received-' + str(fault))
                data = self.bundle.read_bytes()
                if fault == 'corrupt':
                    data = data[:-1] + bytes([data[-1] ^ 1])
                selected = hashlib.sha256(data).hexdigest()
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(2)
                port = listener.getsockname()[1]
                errors, removed = [], []
                def serve():
                    try:
                        for index in range(1 if fault == 'empty' else 2 if fault == 'disconnect' else 3):
                            with listener.accept()[0] as stream:
                                stream.settimeout(2)
                                request = provision.usb.read_exact(stream, 37)
                                if index != 1:
                                    self.assertEqual(request, b'FRK1\x03' + bytes(32))
                                    current = '0' * 64 if fault == 'empty' else 'f' * 64 if fault == 'changed' and index == 2 else selected
                                    stream.sendall(b'\0' + current.encode())
                                else:
                                    self.assertEqual(request, b'FRK1\x02' + bytes.fromhex(selected))
                                    stream.sendall(b'\0' + struct.pack('>Q', len(data)))
                                    stream.sendall(data[:100] if fault == 'disconnect' else data + b'\0')
                    except BaseException as error:
                        errors.append(error)
                worker = threading.Thread(target=serve)
                worker.start()
                class Phone:
                    def forward(self): return port
                    def remove(self, selected_port): removed.append(selected_port)
                try:
                    with patch.object(provision.usb, 'USB', return_value=Phone()), \
                         patch.object(provision.usb, 'connect', side_effect=lambda *args: socket.create_connection(('127.0.0.1', port), timeout=2)):
                        if fault:
                            with self.assertRaises((ValueError, OSError, EOFError)):
                                provision.receive('fixture', serial, state, output)
                            self.assertFalse(output.exists())
                        else:
                            result = provision.receive('fixture', serial, state, output)
                            self.assertEqual(result['sha256'], self.digest)
                            self.assertEqual((output / 'state/desired/profile.json').read_bytes(), self.plain)
                            self.assertEqual((output / 'identity.txt').stat().st_mode & 0o777, 0o600)
                finally:
                    worker.join(timeout=5)
                    listener.close()
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual(removed, [port])
                self.assertFalse(list(self.case.glob('.provision-*')))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--export-fixture':
        Portable.setUpClass()
        case = Portable()
        try:
            case.setUp()
            destination = Path(sys.argv[2])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(case.bundle, destination)
            destination.chmod(0o600)
            print('Synthetic portable fixture created; contains test-only identity.')
        finally:
            case.doCleanups()
            Portable.doClassCleanups()
    else:
        unittest.main(verbosity=2)
