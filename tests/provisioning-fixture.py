"""Synthetic installation fixture. Never reads an operator's keys or state."""
import importlib.util
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vault'))
import portable
import recovery_kit as kit


def create(destination, password, *, recovery=True, account_password=None):
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
        return portable.create(staging, identity, context, capsule, kit.sha(capsule / 'manifest.json') if capsule else None, destination)


if __name__ == '__main__':
    destination = Path(sys.argv[1])
    print(create(destination, 'frankensteintestonly'))
