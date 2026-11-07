"""Native age/SQLite proof for portable Vaultwarden state, synthetic only."""
from datetime import datetime, timezone
from pathlib import Path
import importlib.util
import json
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import vault_provision as provision
from vault_provision import kit, portable, sync, vault


class VaultProvision(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='vault-provision-test-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.pc = self.root / 'ecosystem'
        self.key = self.root / 'vault-key'
        self.device = self.root / 'device-key'
        for key in (self.key, self.device):
            subprocess.run(['age-keygen', '-o', str(key)], check=True, capture_output=True)
            key.chmod(0o600)
        stage = self.root / 'state'
        (stage / 'desired').mkdir(parents=True)
        (stage / 'desired/profile.json').write_bytes(b'{"hostname":"fixture"}')
        context = {'revisions': {'engine': '1' * 40, 'state': '2' * 40},
                   'features': ['fixture'], 'required_owners': ['desired']}
        bundle = self.root / 'initial.fpe'
        portable.create(stage, self.device, context, None, None, bundle)
        portable.restore(bundle, self.pc, kit.sha(bundle))
        data = self.root / 'data'
        data.mkdir()
        with sqlite3.connect(data / 'db.sqlite3') as db:
            db.executescript("CREATE TABLE users(value TEXT); CREATE TABLE ciphers(value TEXT); INSERT INTO ciphers VALUES ('synthetic');")
        db.close()
        (data / 'attachment').write_bytes(b'preserve attachment')
        plain = self.root / 'native.tar.gz'
        with tarfile.open(plain, 'w:gz') as tar:
            tar.add(data, arcname='data')
        self.archive = self.root / 'native.age'
        recipient = vault.run(['age-keygen', '-y', self.key]).decode().strip()
        vault.run(['age', '-r', recipient, '-o', self.archive, plain])
        self.config = {'image': 'vaultwarden/server@sha256:' + '1' * 64,
                       'network_image': 'tailscale/tailscale@sha256:' + '2' * 64,
                       'domain': 'https://original.tailtest.ts.net',
                       'backup_repository': 'fixture/private-state', 'backup_branch': 'main',
                       'network_private_identity': 'MUST NOT TRAVEL'}
        self.receipt = {'sha256': kit.sha(self.archive), 'image': self.config['image'],
                        'created_at': datetime.now(timezone.utc).isoformat()}

    def attach(self, **kwargs):
        return provision.attach(self.pc, self.archive, self.key, self.receipt, self.config, **kwargs)

    def test_attach_restore_preserves_identity_state_and_retains_generation(self):
        before = sync.summary(self.pc)
        old_identity = (self.pc / 'identity.txt').read_bytes()
        result = self.attach()
        current = sync.summary(self.pc)
        self.assertEqual(before['kit_id'], current['kit_id'])
        self.assertEqual(old_identity, (self.pc / 'identity.txt').read_bytes())
        self.assertEqual(before, sync.summary(Path(result['retained_pc'])))
        self.assertEqual((self.pc / 'state/desired/profile.json').read_bytes(), b'{"hostname":"fixture"}')
        value = json.loads((self.pc / 'state' / provision.DESIRED).read_bytes())
        self.assertNotIn('network_private_identity', value)
        output = self.root / 'service'
        prepared = provision.restore(self.pc, output)
        self.assertEqual(prepared['state'], 'stopped')
        self.assertEqual(prepared['preferred_url'], self.config['domain'])
        self.assertEqual((output / 'data/attachment').read_bytes(), b'preserve attachment')
        self.assertEqual(vault.database(output / 'data'), {'users': 0, 'ciphers': 1})
        self.assertFalse((output / 'network').exists())
        self.assertEqual((output / 'identity.txt').stat().st_mode & 0o077, 0)
        service = vault.Service(output / 'service.json')
        service.prepare()  # Config resolves to the final directory, not temporary staging.
        self.assertEqual(service.data, output / 'data')
        self.assertEqual(service.config['domain'], self.config['domain'])

    def test_wrong_opening_or_hash_never_changes_ecosystem(self):
        before = sync.inventory(self.pc)
        with self.assertRaises(vault.Error):
            provision.attach(self.pc, self.archive, self.device, self.receipt, self.config)
        self.assertEqual(before, sync.inventory(self.pc))
        self.receipt['sha256'] = '0' * 64
        with self.assertRaises(vault.Error):
            self.attach()
        self.assertEqual(before, sync.inventory(self.pc))

    def test_existing_selection_requires_exact_explicit_replacement(self):
        self.attach()
        before = sync.inventory(self.pc)
        for expected in (None, '0' * 64):
            with self.assertRaises(kit.KitError):
                self.attach(replace_sha=expected)
            self.assertEqual(before, sync.inventory(self.pc))
        self.attach(replace_sha=self.receipt['sha256'])

    def test_existing_service_is_untouched_even_when_empty(self):
        self.attach()
        output = self.root / 'existing'
        output.mkdir()
        with self.assertRaisesRegex(kit.KitError, 'EXISTS_PRESERVED'):
            provision.restore(self.pc, output)
        self.assertEqual(list(output.iterdir()), [])
        (output / 'sentinel').write_bytes(b'original')
        with self.assertRaisesRegex(kit.KitError, 'EXISTS_PRESERVED'):
            provision.restore(self.pc, output)
        self.assertEqual((output / 'sentinel').read_bytes(), b'original')

    def test_unsaved_local_edit_is_not_a_verified_selected_generation(self):
        self.attach()
        (self.pc / 'state' / provision.ARCHIVE).write_bytes(b'edited')
        output = self.root / 'service'
        with self.assertRaisesRegex(kit.KitError, 'LOCAL_SELECTION_CHANGED'):
            provision.restore(self.pc, output)
        self.assertFalse(output.exists())

    def test_concurrent_pc_edit_cannot_be_lost(self):
        original = portable.create
        def concurrent(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.pc / 'state/desired/profile.json').write_bytes(b'concurrent owner edit')
            return result
        with patch.object(portable, 'create', concurrent):
            with self.assertRaisesRegex(kit.KitError, 'SYNC_PC_CHANGED'):
                self.attach()
        self.assertEqual((self.pc / 'state/desired/profile.json').read_bytes(), b'concurrent owner edit')
        self.assertFalse((self.pc / 'state' / provision.DESIRED).exists())

    def test_concurrent_destination_creation_cannot_be_overwritten(self):
        self.attach()
        output = self.root / 'service'
        original = kit.publish_directory
        def raced(source, destination):
            if destination == output:
                output.mkdir()
                (output / 'owner').write_bytes(b'existing service')
            return original(source, destination)
        with patch.object(kit, 'publish_directory', raced):
            with self.assertRaisesRegex(kit.KitError, 'OUTPUT_EXISTS'):
                provision.restore(self.pc, output)
        self.assertEqual((output / 'owner').read_bytes(), b'existing service')
        self.assertFalse((output / 'data').exists())

    def test_cli_restore_reports_no_secret_and_preserves_existing_target(self):
        self.attach()
        output = self.root / 'cli-service'
        args = [sys.executable, str(ROOT / 'lib/vault_provision.py'), 'restore', '--ecosystem', str(self.pc), '--output', str(output)]
        result = subprocess.run(args, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b'AGE-SECRET-KEY-', result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['state'], 'stopped')
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 2)

    def test_installer_fixture_has_restorable_native_state(self):
        spec = importlib.util.spec_from_file_location('fixture', ROOT / 'tests/provisioning-fixture.py')
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        bundle = self.root / 'install.fpe'
        fixture.create(bundle, 'synthetic-disk-only', recovery=False, account_password='1234', vaultwarden=True)
        ecosystem = self.root / 'installed'
        portable.restore(bundle, ecosystem, kit.sha(bundle))
        output = self.root / 'installed-service'
        provision.restore(ecosystem, output)
        self.assertEqual((output / 'data/fixture').read_bytes(), b'portable-vaultwarden-preserved')
        self.assertEqual(json.loads((output / 'service.json').read_bytes())['domain'], 'https://preserved.tailfixture.ts.net')

    def test_existing_recovery_capsule_is_preserved_after_attach(self):
        spec = importlib.util.spec_from_file_location('fixture', ROOT / 'tests/provisioning-fixture.py')
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        bundle = self.root / 'recovery.fpe'
        fixture.create(bundle, 'synthetic-disk-only', recovery=True)
        ecosystem = self.root / 'recovery-ecosystem'
        portable.restore(bundle, ecosystem, kit.sha(bundle))
        before = sync.summary(ecosystem)
        capsule = {p.name: p.read_bytes() for p in (ecosystem / 'recovery').iterdir()}
        provision.attach(ecosystem, self.archive, self.key, self.receipt, self.config)
        after = sync.summary(ecosystem)
        self.assertEqual(before['kit_id'], after['kit_id'])
        self.assertEqual(before['recipient'], after['recipient'])
        self.assertEqual(before['recovery'], after['recovery'])
        self.assertEqual(capsule, {p.name: p.read_bytes() for p in (ecosystem / 'recovery').iterdir()})


if __name__ == '__main__':
    unittest.main()
