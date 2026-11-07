import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vaultwarden', Path(__file__).resolve().parents[1] / 'vault/vaultwarden.py')
vault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vault)


class Restores(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        with sqlite3.connect(self.source / 'db.sqlite3') as db:
            db.executescript('CREATE TABLE users(id); INSERT INTO users VALUES (1); CREATE TABLE ciphers(id); INSERT INTO ciphers VALUES (7);')
        (self.source / 'attachments').mkdir()
        (self.source / 'attachments/item').write_bytes(b'synthetic attachment')
        self.archive = self.root / 'archive.tar.gz'
        self.identity = self.root / 'dummy.key'
        self.identity.write_text('not a real key')
        self.destination = self.root / 'restored'

    def make(self, extra=None):
        with tarfile.open(self.archive, 'w:gz') as tar:
            tar.add(self.source, arcname='data')
            if extra:
                tar.addfile(extra, io.BytesIO(b'x' * extra.size) if extra.isfile() else None)
        return vault.digest(self.archive)

    def decrypt(self, command, timeout=0):
        shutil.copyfile(self.archive, command[command.index('--output') + 1])
        return b''

    def restore(self, checksum=None):
        with patch.object(vault, 'run', self.decrypt):
            return vault.restore(self.archive, self.identity, self.destination, checksum or self.make())

    def test_restore_keeps_database_and_attachments_private(self):
        result = self.restore()
        self.assertEqual(result['database'], {'users': 1, 'ciphers': 1})
        self.assertEqual((self.destination / 'attachments/item').read_bytes(), b'synthetic attachment')
        self.assertEqual((self.destination / 'db.sqlite3').stat().st_mode & 0o777, 0o600)

    def test_existing_data_is_never_replaced(self):
        self.destination.mkdir()
        (self.destination / 'keep').write_text('old data')
        with self.assertRaisesRegex(vault.Error, 'destination exists'):
            self.restore()
        self.assertEqual((self.destination / 'keep').read_text(), 'old data')

    def test_bad_digest_refused_before_decrypt(self):
        self.make()
        with patch.object(vault, 'run') as provider, self.assertRaises(vault.Error):
            vault.restore(self.archive, self.identity, self.destination, '0' * 64)
        provider.assert_not_called()

    def test_authentication_failure_leaves_no_materialized_vault(self):
        checksum = self.make()
        with patch.object(vault, 'run', side_effect=vault.Error('age authentication failed')), self.assertRaises(vault.Error):
            vault.restore(self.archive, self.identity, self.destination, checksum)
        self.assertFalse(self.destination.exists())
        self.assertFalse(list(self.root.glob('.restore-*')))

    def test_traversal_absolute_duplicate_and_special_files_rejected(self):
        for path, kind in [('data/../../outside', tarfile.REGTYPE), ('/data/outside', tarfile.REGTYPE),
                           ('data/db.sqlite3', tarfile.REGTYPE), ('data/link', tarfile.SYMTYPE),
                           ('data/hardlink', tarfile.LNKTYPE), ('data/pipe', tarfile.FIFOTYPE)]:
            member = tarfile.TarInfo(path)
            member.type = kind
            member.linkname = '/etc/passwd'
            checksum = self.make(member)
            with self.subTest(path=path), self.assertRaises(vault.Error):
                self.restore(checksum)
            self.assertFalse(self.destination.exists())

    def test_invalid_database_never_publishes_restore(self):
        (self.source / 'db.sqlite3').write_bytes(b'invalid database')
        with self.assertRaises(sqlite3.Error):
            self.restore()
        self.assertFalse(self.destination.exists())

    def test_symlinked_storage_refused(self):
        self.destination.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(vault.Error):
            self.restore()

    def test_live_inventory_rejects_symlink(self):
        (self.source / 'link').symlink_to(self.identity)
        with self.assertRaises(vault.Error):
            vault.inventory(self.source)

    def service(self, domain='https://original.tail-example.ts.net'):
        configuration = self.root / 'service.json'
        vault.save(configuration, {'schema': 1, 'state': str(self.root), 'project': 'fixture-vault',
            'image': 'vaultwarden/server@sha256:' + 'a' * 64,
            'network_image': 'tailscale/tailscale@sha256:' + 'b' * 64, 'domain': domain})
        return vault.Service(configuration)

    def test_existing_address_is_retained_when_a_new_network_identity_appears(self):
        service = self.service()
        network = json.dumps({'BackendState': 'Running', 'Self': {'DNSName': 'replacement.tail-example.ts.net.'}}).encode()
        with patch.object(service, 'compose', return_value=network) as native:
            with self.assertRaisesRegex(vault.Error, 'existing Vault address differs'):
                service.connect()
        self.assertEqual(native.call_count, 1)
        self.assertEqual(json.loads(service.file.read_text())['domain'], 'https://original.tail-example.ts.net')
        self.assertEqual(json.loads(service.compose_file.read_text())['services']['vaultwarden']['environment']['DOMAIN'],
                         'https://original.tail-example.ts.net')

    def test_explicit_address_replacement_retains_previous_service_configuration(self):
        service = self.service()
        network = json.dumps({'BackendState': 'Running', 'Self': {'DNSName': 'replacement.tail-example.ts.net.'}}).encode()
        with patch.object(service, 'compose', return_value=network), patch.object(service, 'healthy'):
            self.assertEqual(service.connect(replace_address=True)['url'], 'https://replacement.tail-example.ts.net')
        previous = list(self.root.glob('compose-before-*.json'))
        self.assertEqual(len(previous), 1)
        self.assertEqual(json.loads(previous[0].read_text())['services']['vaultwarden']['environment']['DOMAIN'],
                         'https://original.tail-example.ts.net')


if __name__ == '__main__':
    unittest.main()
