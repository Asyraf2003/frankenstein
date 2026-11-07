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
from types import SimpleNamespace
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vault'))
import portable
import recovery_kit as kit
import recovery_opening as opening
import recovery_backup
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

    def test_native_enrollment_restores_without_original_device_using_recovery(self):
        phrase = secrets.token_urlsafe(32)
        request = {'context': self.context, 'files': {'desired/profile.json': base64.b64encode(self.plain).decode()},
                   'recovery_passphrase': phrase}
        result = subprocess.run([str(BRIDGE), 'enroll'], input=kit.encoded(request), capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, 'Native enrollment failed; private output withheld')
        self.assertEqual(result.stderr, b'')
        self.assertNotIn(phrase.encode(), result.stdout)
        # GitHub onboarding amends the same identity and independent capsule.
        original = result.stdout
        original_header = json.loads(original[8:8 + struct.unpack('>I', original[4:8])[0]])
        before = json.loads(subprocess.run([str(BRIDGE), 'verify'], input=original, capture_output=True, check=True).stdout)
        credential = kit.encoded({'access_token': 'synthetic_github_token_only'})
        patch_request = kit.encoded({'path': 'credentials/github.json', 'base64': base64.b64encode(credential).decode()})
        result = subprocess.run([str(BRIDGE), 'amend-github'],
            input=struct.pack('>I', len(patch_request)) + patch_request + original, capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, 'Amendment failed; private output withheld')
        self.assertNotIn(b'synthetic_github_token_only', result.stdout)
        updated_header = json.loads(result.stdout[8:8 + struct.unpack('>I', result.stdout[4:8])[0]])
        for field in ('identity', 'context', 'recovery', 'recovery_manifest_sha256'):
            self.assertTrue(original_header[field] == updated_header[field], 'Identity/recovery changed')
        after = json.loads(subprocess.run([str(BRIDGE), 'verify'], input=result.stdout, capture_output=True, check=True).stdout)
        self.assertEqual(before['manifest']['kit_id'], after['manifest']['kit_id'])
        bundle = self.case / 'enrolled.fpe'
        bundle.write_bytes(result.stdout)
        restored = self.case / 'enrolled'
        portable.restore(bundle, restored, kit.sha(bundle))
        self.assertEqual((restored / 'state/desired/profile.json').read_bytes(), self.plain)
        self.assertEqual((restored / 'state/credentials/github.json').read_bytes(), credential)
        # Delete the portable opening key and bundle. Recovery has only the
        # independently encrypted identity, ciphertext archive and external phrase.
        (restored / 'identity.txt').unlink()
        bundle.unlink()
        recovered = self.case / 'recovery.tar'
        code, _, supplied = helper.tty(['age', '--decrypt', '--identity', restored / 'recovery/identity.age',
                                       '--output', recovered, restored / 'vault.age'], [phrase], native=True)
        self.assertEqual((code, supplied), (0, 1), 'Recovery failed; transcript withheld')
        with tarfile.open(recovered) as archive:
            self.assertEqual(archive.extractfile('payload/desired/profile.json').read(), self.plain)
            self.assertEqual(archive.extractfile('payload/credentials/github.json').read(), credential)
        exported = self.case / 'backup.zip'
        with zipfile.ZipFile(exported, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name in ('vault.age', 'context.json', 'recovery/identity.age', 'recovery/recipient.txt', 'recovery/manifest.json'):
                archive.write(restored / name, name)
            archive.writestr('selection.json', kit.encoded({'schema': 1,
                'archive_sha256': kit.sha(restored / 'vault.age'),
                'recovery_manifest_sha256': kit.sha(restored / 'recovery/manifest.json')}))
        recoveredDirectory = self.case / 'zip-restored'
        code, _, supplied = helper.tty([ROOT / 'vault/recovery_backup.py', '--source', exported,
            '--output', recoveredDirectory, '--sha256', kit.sha(exported)], [phrase])
        self.assertEqual((code, supplied), (0, 1), 'Backup restore failed; transcript withheld')
        self.assertEqual((recoveredDirectory / 'state/desired/profile.json').read_bytes(), self.plain)
        self.assertEqual((recoveredDirectory / 'state/credentials/github.json').read_bytes(), credential)
        self.assertEqual((recoveredDirectory / 'identity.txt').stat().st_mode & 0o777, 0o600)
        wrongDirectory = self.case / 'wrong-recovery'
        code, _, supplied = helper.tty([ROOT / 'vault/recovery_backup.py', '--source', exported,
            '--output', wrongDirectory, '--sha256', kit.sha(exported)], ['wrong-synthetic-passphrase'])
        self.assertNotEqual(code, 0)
        self.assertFalse(wrongDirectory.exists())
        self.assertFalse(list(self.case.glob('.recovery-*')))
        request['recovery_passphrase'] = 'too-short'
        rejected = subprocess.run([str(BRIDGE), 'enroll'], input=kit.encoded(request), capture_output=True, timeout=30)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(rejected.stdout, b'')

    def test_amend_replacement_and_untrusted_input_fail_closed(self):
        original = self.bundle.read_bytes()
        def amend_bytes(bundle, path='credentials/github.json', data=b'{"fixture":1}'):
            request = kit.encoded({'path': path, 'base64': base64.b64encode(data).decode()})
            return subprocess.run([str(BRIDGE), 'amend-github'], input=struct.pack('>I', len(request)) + request + bundle,
                                  capture_output=True, timeout=30)
        first = amend_bytes(original)
        self.assertEqual(first.returncode, 0, 'Amendment failed; private output withheld')
        second = amend_bytes(first.stdout, data=b'{"fixture":2}')
        self.assertEqual(second.returncode, 0, 'Replacement failed; private output withheld')
        read = subprocess.run([str(BRIDGE), 'read', 'credentials/github.json'], input=second.stdout, capture_output=True, check=True)
        self.assertEqual(base64.b64decode(json.loads(read.stdout)['selected']['base64']), b'{"fixture":2}')
        for candidate, path, data in (
            (original[:-1] + bytes([original[-1] ^ 1]), 'credentials/github.json', b'{}'),
            (original, 'credentials/../escape.json', b'{}'),
            (original, 'desired/profile.json', b'{}'),
            (original, 'credentials/github.json', b'{"duplicate":1,"duplicate":2}'),
            (original, 'credentials/github.json', b' ' * 65537),
            (original + bytes(16 * 1024 * 1024), 'credentials/github.json', b'{}'),
        ):
            rejected = amend_bytes(candidate, path, data)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(rejected.stdout, b'')
            self.assertEqual(rejected.stderr, b'VAULT_AMENDMENT_FAILED\n')

    def test_recovery_zip_rejects_extra_paths_before_extracting(self):
        bad = self.case / 'traversal.zip'
        with zipfile.ZipFile(bad, 'w') as archive:
            for name in recovery_backup.FILES:
                archive.writestr(name, b'fixture')
            archive.writestr('../escaped', b'bad')
        destination = self.case / 'unpacked'
        destination.mkdir()
        with self.assertRaisesRegex(kit.KitError, 'LAYOUT_INVALID'):
            recovery_backup.unpack(bad, destination)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertFalse((self.case / 'escaped').exists())

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

    def test_restore_keeps_temporary_plaintext_on_destination_filesystem(self):
        # A live ISO's default tmpfs may be unavailable or too small. Restoring
        # must use the selected destination volume for all temporary archives.
        with patch.object(tempfile, 'tempdir', str(self.case / 'unavailable-tmpfs')):
            restored = self.case / 'disk-backed-restore'
            portable.restore(self.bundle, restored, self.digest)
        self.assertEqual((restored / 'state/desired/profile.json').read_bytes(), self.plain)

    def test_installer_consumes_verified_identity_and_retains_independent_vault(self):
        def module(name, path):
            spec = importlib.util.spec_from_file_location(name, path)
            result = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(result)
            return result
        fixture = module('install_fixture', ROOT / 'tests/provisioning-fixture.py')
        installer = module('native_installer', ROOT / 'installer/install.py')
        bundle = self.case / 'installation.fpe'
        digest = fixture.create(bundle, 'synthetic-account-disk-only')
        args = SimpleNamespace(phone=None, provisioning_bundle=bundle, sha256=digest)
        staging = self.case / 'bootstrap'
        staging.mkdir()
        config, password, disk, supplied = installer.provision_input(args, staging)
        self.assertEqual(config['username'], 'proof')
        self.assertEqual(password, 'synthetic-account-disk-only')
        self.assertEqual(password, disk)
        supplied['recheck']()
        restored = self.case / 'encrypted-root-fixture'
        supplied['restore'](restored)
        self.assertEqual((restored / 'state/desired/tuning.json').read_bytes(),
                         b'{"fixture":"portable-tuning-preserved"}\n')
        context = kit.decode((restored / 'context.json').read_bytes())
        self.assertTrue(kit.inspect(restored / 'vault.age', restored / 'identity.txt', context))
        with bundle.open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaisesRegex(installer.Error, 'changed'):
            supplied['recheck']()

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
