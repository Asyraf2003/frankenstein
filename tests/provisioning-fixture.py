"""Synthetic installation fixture. Never reads an operator's keys or state."""
import importlib.util
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vault'))
import portable
import recovery_kit as kit


def create(destination, password, *, recovery=True, account_password=None, vaultwarden=False):
    spec = importlib.util.spec_from_file_location('opening_test', ROOT / 'tests/native-vault-opening.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    with tempfile.TemporaryDirectory(prefix='install-fixture-', dir=destination.parent) as temporary:
        root = Path(temporary)
        capsule = root / 'recovery' if recovery else None
        if recovery:
            phrase = secrets.token_urlsafe(32)
            code, _, supplied = helper.tty([ROOT / 'vault/recovery_opening.py', 'enroll', '--opening', capsule], [phrase] * 3)
            if code != 0 or supplied != 3:
                raise RuntimeError('Synthetic recovery enrollment failed; transcript withheld')
        identity = root / 'identity.txt'
        subprocess.run(['age-keygen', '-o', str(identity)], check=True, capture_output=True)
        identity.chmod(0o600)
        staging = root / 'state'
        for owner in ('desired', 'credentials'):
            (staging / owner).mkdir(mode=0o700, parents=True)
        (staging / 'desired/arch.json').write_bytes(kit.encoded({
            'username': 'proof', 'hostname': 'proof', 'timezone': 'UTC', 'packages': ['wmctrl', 'xorg-xprop']}))
        (staging / 'desired/tuning.json').write_bytes(b'{"fixture":"portable-tuning-preserved"}\n')
        (staging / 'credentials/arch-install.json').write_bytes(kit.encoded({
            'password': account_password if account_password is not None else password, 'disk_passphrase': password}))
        context = {'revisions': {'engine': '1' * 40, 'state': '2' * 40},
                   'features': ['synthetic-installation'], 'required_owners': ['desired', 'credentials']}
        if vaultwarden:
            native = root / 'vault-data'
            native.mkdir()
            with sqlite3.connect(native / 'db.sqlite3') as db:
                db.executescript('CREATE TABLE users(value TEXT); CREATE TABLE ciphers(value TEXT);')
            db.close()
            (native / 'fixture').write_bytes(b'portable-vaultwarden-preserved')
            archive = root / 'native.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                tar.add(native, arcname='data')
            key = staging / 'keyring/vaultwarden/identity.txt'
            key.parent.mkdir(mode=0o700, parents=True)
            subprocess.run(['age-keygen', '-o', str(key)], check=True, capture_output=True)
            key.chmod(0o600)
            recipient = subprocess.check_output(['age-keygen', '-y', str(key)], text=True).strip()
            ciphertext = staging / 'vault/vaultwarden/native.age'
            ciphertext.parent.mkdir(mode=0o700, parents=True)
            subprocess.run(['age', '-r', recipient, '-o', str(ciphertext), str(archive)], check=True, capture_output=True)
            (staging / 'desired/vaultwarden.json').write_bytes(kit.encoded({
                'schema': 1, 'format': 'vaultwarden-native-age-tar', 'sha256': kit.sha(ciphertext),
                'created_at': '2026-11-07T00:00:00+00:00',
                'image': 'vaultwarden/server@sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055',
                'network_image': 'tailscale/tailscale@sha256:ed6480b33c6eb67c9cbd203ed42b9fb57e361986725b6856def71b7a3d9e276c',
                'domain': 'https://preserved.tailfixture.ts.net', 'backup_repository': None, 'backup_branch': None}))
            context['features'].append('vaultwarden')
            context['required_owners'].extend(['keyring', 'vault'])
        return portable.create(staging, identity, context, capsule, kit.sha(capsule / 'manifest.json') if capsule else None, destination)


if __name__ == '__main__':
    destination = Path(sys.argv[1])
    print(create(destination, 'frankensteintestonly'))
