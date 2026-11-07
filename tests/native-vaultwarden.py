"""Disposable real Vaultwarden/Docker/age capture-and-restore proof."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from unittest.mock import patch

sys.path.insert(0, os.environ.get('FRANKENSTEIN_TEST_RUNTIME', str(Path(__file__).resolve().parents[1] / 'lib')))
import vault_provision as provisioning

spec = importlib.util.spec_from_file_location('vaultwarden', Path(__file__).resolve().parents[1] / 'vault/vaultwarden.py')
vault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vault)
parser = argparse.ArgumentParser()
parser.add_argument('--image', required=True)
parser.add_argument('--network-image', required=True)
args = parser.parse_args()
project = 'frankenstein-proof-' + uuid.uuid4().hex[:8]
with tempfile.TemporaryDirectory(prefix='vaultwarden-native-') as temporary:
    root = Path(temporary)
    data = vault.private(root / 'data')
    seed = project + '-seed'
    service = None
    restored_service = None
    try:
        vault.run(['docker', 'run', '-d', '--name', seed, '--mount', 'type=bind,src=' + str(data) + ',dst=/data', args.image])
        for _ in range(60):
            health = subprocess.run(['docker', 'exec', seed, '/healthcheck.sh'], capture_output=True)
            if health.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('fixture service did not become healthy')
        vault.run(['docker', 'stop', '--time', '60', seed])
        vault.run(['docker', 'rm', seed])
        with sqlite3.connect(data / 'db.sqlite3') as db:
            db.executescript("CREATE TABLE fixture_marker(value TEXT); INSERT INTO fixture_marker VALUES ('synthetic owner state');")
        db.close()
        (data / 'attachments').mkdir(exist_ok=True)
        (data / 'attachments/fixture').write_bytes(b'synthetic attachment preserved')
        key = root / 'identity.txt'
        vault.run(['age-keygen', '-o', key])
        recipient = root / 'recipient.txt'
        recipient.write_bytes(vault.run(['age-keygen', '-y', key]))
        config = root / 'service.json'
        vault.save(config, {'schema': 1, 'state': str(root), 'project': project, 'port': 18229,
                           'image': args.image, 'network_image': args.network_image, 'recipient': str(recipient)})
        service = vault.Service(config)
        assert service.on()['state'] == 'running'
        receipt = service.backup()
        assert receipt['service_resumed'] and service.status()['state'] == 'running'
        restored = root / 'restored'
        vault.restore(root / 'backups' / receipt['archive'], key, restored, receipt['sha256'])
        assert (restored / 'attachments/fixture').read_bytes() == b'synthetic attachment preserved'
        with sqlite3.connect(restored / 'db.sqlite3') as db:
            assert db.execute('SELECT value FROM fixture_marker').fetchone() == ('synthetic owner state',)
        db.close()
        original_run = vault.run
        completed = set((root / 'backups').iterdir())
        def failed_age(command, **kwargs):
            if command[0] == 'age':
                raise vault.Error('fixture encryption failure')
            return original_run(command, **kwargs)
        with patch.object(vault, 'run', failed_age):
            try:
                service.backup()
            except vault.Error as error:
                assert str(error) == 'fixture encryption failure'
            else:
                raise AssertionError('expected encryption failure')
        assert service.status()['state'] == 'running' and not service.status()['backup_pending']
        assert set((root / 'backups').iterdir()) == completed
        def lost_start_reply(command, **kwargs):
            result = original_run(command, **kwargs)
            if command[:2] == ['docker', 'start']:
                raise vault.Error('fixture lost start reply')
            return result
        with patch.object(vault, 'run', lost_start_reply):
            try:
                service.backup()
            except vault.Error as error:
                assert str(error) == 'fixture lost start reply'
            else:
                raise AssertionError('expected lost reply')
        assert service.status()['state'] == 'running' and not service.status()['backup_pending']
        assert set((root / 'backups').iterdir()) == completed
        service.off()
        stopped = service.backup()
        assert not stopped['service_resumed'] and service.status()['state'] == 'stopped'
        # Use the actual completed native capture through the portable owner
        # pipeline, then start the restored database in another isolated service.
        staged = root / 'owners'
        (staged / 'desired').mkdir(parents=True)
        (staged / 'desired/profile.json').write_bytes(b'{"fixture":true}')
        context = {'revisions': {'engine': '1' * 40, 'state': '2' * 40},
                   'features': ['fixture'], 'required_owners': ['desired']}
        bundle = root / 'initial.fpe'
        provisioning.portable.create(staged, key, context, None, None, bundle)
        ecosystem = root / 'ecosystem'
        provisioning.portable.restore(bundle, ecosystem, provisioning.kit.sha(bundle))
        provisioning.attach(ecosystem, root / 'backups' / stopped['archive'], key, stopped, service.config)
        destination = root / 'provisioned'
        provisioning.restore(ecosystem, destination, project=project + '-new', port=18230)
        restored_service = vault.Service(destination / 'service.json')
        assert restored_service.on()['state'] == 'running'
        assert (destination / 'data/attachments/fixture').read_bytes() == b'synthetic attachment preserved'
        assert service.status()['state'] == 'stopped'
        if os.geteuid() == 0:
            # Real root-owned Docker capture attached by the unprivileged owner;
            # later user sync must retain access to its lock, history and files.
            account = pwd.getpwnam('nobody')
            with tempfile.TemporaryDirectory(prefix='vault-owner-proof-') as owner_temp:
                owner_root = Path(owner_temp)
                owner_ecosystem = owner_root / 'ecosystem'
                provisioning.portable.restore(bundle, owner_ecosystem, provisioning.kit.sha(bundle))
                for path in [owner_root, *owner_root.rglob('*')]:
                    os.chown(path, account.pw_uid, account.pw_gid)
                provisioning.capture(owner_ecosystem, config, key)
                for path in [owner_ecosystem, *owner_ecosystem.rglob('*'), * (owner_root / '.ecosystem-sync').rglob('*')]:
                    assert path.stat().st_uid == account.pw_uid
                assert (owner_ecosystem / 'state' / provisioning.DESIRED).is_file()
        print('NATIVE_VAULTWARDEN=PASS running-capture-resume,stopped-capture,age-restore,sqlite,attachment,encryption-failure,lost-start-reply')
        print('NATIVE_VAULTWARDEN_PROVISION=PASS native-capture,portable-state,fresh-service-health,original-service-preserved')
    finally:
        subprocess.run(['docker', 'rm', '-f', seed], capture_output=True)
        if service:
            service.compose('down')
        if restored_service:
            restored_service.compose('down')
