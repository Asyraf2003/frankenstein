"""Carry a native Vaultwarden capture inside the existing private ecosystem."""
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sys
import subprocess
import tempfile
import uuid

import device_sync as sync
from device_sync import kit, portable
import vaultwarden as vault

DESIRED = 'desired/vaultwarden.json'
IDENTITY = 'keyring/vaultwarden/identity.txt'
ARCHIVE = 'vault/vaultwarden/native.age'
FILES = (DESIRED, IDENTITY, ARCHIVE)


def descriptor(value):
    kit.require(isinstance(value, dict) and set(value) == {
        'schema', 'format', 'sha256', 'created_at', 'image', 'network_image', 'domain',
        'backup_repository', 'backup_branch'}, 'VAULT_SELECTION_INVALID')
    kit.require(value['schema'] == 1 and value['format'] == 'vaultwarden-native-age-tar', 'VAULT_FORMAT_INVALID')
    kit.require(isinstance(value['sha256'], str) and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'VAULT_DIGEST_INVALID')
    kit.require(re.fullmatch('vaultwarden/server@sha256:[0-9a-f]{64}', value['image'])
                and re.fullmatch('tailscale/tailscale@sha256:[0-9a-f]{64}', value['network_image']), 'VAULT_IMAGE_NOT_PINNED')
    kit.require(value['domain'] is None or re.fullmatch(r'https://[a-z0-9-]+\.[a-z0-9-]+\.ts\.net', value['domain']), 'VAULT_DOMAIN_INVALID')
    kit.require((value['backup_repository'] is None) == (value['backup_branch'] is None), 'VAULT_BACKUP_SELECTION_INVALID')
    if value['backup_repository'] is not None:
        kit.require(re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value['backup_repository'])
                    and re.fullmatch('[A-Za-z0-9][A-Za-z0-9/_.-]*', value['backup_branch'])
                    and '..' not in value['backup_branch'], 'VAULT_BACKUP_SELECTION_INVALID')
    kit.require(datetime.fromisoformat(value['created_at']).tzinfo is not None, 'VAULT_TIMESTAMP_INVALID')
    return value


def write(path, content):
    kit.private_directories(path.parent)
    with path.open('wb') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def attach(root, archive, identity, receipt, config, *, replace_sha=None):
    """Add a verified capture, retaining prior state and its identity/recovery key.

    Inputs are an immutable completed Service.backup receipt, its ciphertext,
    and the original native opening key. No Docker or network identity is copied.
    Run as the ecosystem owner; privileged service capture remains separate.
    """
    root, archive, identity = map(kit.outside_git, (root, archive, identity))
    kit.require(root.is_dir() and root.stat().st_uid == os.geteuid()
                and root.stat().st_mode & 0o077 == 0, 'ECOSYSTEM_OWNER_REQUIRED')
    kit.require(identity.is_file() and identity.stat().st_size <= 4096
                and identity.stat().st_mode & 0o077 == 0, 'VAULT_OPENING_NOT_PRIVATE')
    value = descriptor({'schema': 1, 'format': 'vaultwarden-native-age-tar',
        'sha256': receipt['sha256'], 'created_at': receipt['created_at'], 'image': receipt['image'],
        'network_image': config['network_image'], 'domain': config.get('domain'),
        'backup_repository': config.get('backup_repository'), 'backup_branch': config.get('backup_branch')})
    kit.require(value['image'] == config['image'], 'VAULT_CAPTURE_IMAGE_CHANGED')
    history = kit.safe(root.parent / ('.' + root.name + '-sync'))
    with kit.writer(history), tempfile.TemporaryDirectory(prefix='.vault-attach-', dir=root.parent) as temporary:
        work = Path(temporary)
        before = sync.inventory(root)
        base = sync.summary(root)
        kit.inventory(root / 'state')
        copied = work / 'source'
        shutil.copytree(root, copied)
        old = copied / 'state' / DESIRED
        if old.exists():
            selected = descriptor(kit.decode(old.read_bytes()))
            kit.require(replace_sha == selected['sha256'], 'VAULT_SELECTION_EXISTS_USE_REPLACE_SHA')
        else:
            kit.require(replace_sha is None, 'VAULT_SELECTION_STALE')
            kit.require(not any((copied / 'state' / name).exists() for name in (IDENTITY, ARCHIVE)), 'VAULT_PARTIAL_SELECTION_EXISTS')
        target = copied / 'state'
        write(target / DESIRED, kit.encoded(value))
        write(target / IDENTITY, identity.read_bytes())
        kit.private_directories((target / ARCHIVE).parent)
        shutil.copyfile(archive, target / ARCHIVE)
        (target / ARCHIVE).chmod(0o600)
        # Verify actual native decryption and database before accepting a key.
        vault.restore(target / ARCHIVE, target / IDENTITY, work / 'native-proof', value['sha256'])
        ctx = dict(base['context'])
        ctx['features'] = sorted(set(ctx['features']) | {'vaultwarden'})
        ctx['required_owners'] = sorted(set(ctx['required_owners']) | {'desired', 'keyring', 'vault'})
        bundle = work / 'candidate.fpe'
        portable.create(target, copied / 'identity.txt', ctx,
                        copied / 'recovery' if base['recovery'] else None, base['recovery'], bundle,
                        kit_id=base['kit_id'])
        ready = work / 'ready'
        portable.restore(bundle, ready, kit.sha(bundle))
        kit.require(sync.inventory(root) == before, 'SYNC_PC_CHANGED')
        retained = history / ('generation-' + uuid.uuid4().hex)
        kit.publish_directory(ready, retained)
        result = {'action': 'attach-vaultwarden', 'sha256': value['sha256'], 'created_at': value['created_at']}
        sync.record(history, result, 'exchanging', retained.name)
        kit.require(sync.inventory(root) == before, 'SYNC_PC_CHANGED')
        sync.exchange(retained, root)
        sync.record(history, result, 'complete', retained.name)
        return {**result, 'retained_pc': str(retained), 'phone': 'use sync preview before selecting a direction'}


def restore(root, output, *, project='frankenstein-vault', port=8222):
    """Prepare a stopped service in a NEW private directory. Never replace a service."""
    root, output = map(kit.outside_git, (root, output))
    kit.require(not output.exists(), 'VAULT_SERVICE_EXISTS_PRESERVED')
    kit.require(re.fullmatch('[a-z][a-z0-9-]{2,40}', project), 'VAULT_PROJECT_INVALID')
    kit.require(type(port) is int and 1024 <= port <= 65535, 'VAULT_PORT_INVALID')
    kit.private_directories(output.parent)
    with tempfile.TemporaryDirectory(prefix='.vault-provision-', dir=output.parent) as temporary:
        work = Path(temporary)
        before = sync.inventory(root)
        base = sync.summary(root)
        # Materialize from authenticated ciphertext; edited owner files are not
        # silently interpreted as the selected phone/PC generation.
        kit.materialize(root / 'vault.age', root / 'identity.txt', base['context'],
                        work / 'selected', kit.sha(root / 'vault.age'))
        selected = work / 'selected'
        value = descriptor(kit.decode((selected / DESIRED).read_bytes()))
        kit.require(all(kit.sha(root / 'state' / name) == kit.sha(selected / name) for name in FILES), 'VAULT_LOCAL_SELECTION_CHANGED')
        ready = work / 'ready'
        ready.mkdir(mode=0o700)
        vault.restore(selected / ARCHIVE, selected / IDENTITY, ready / 'data', value['sha256'])
        write(ready / 'identity.txt', (selected / IDENTITY).read_bytes())
        write(ready / 'recipient.txt', vault.run(['age-keygen', '-y', ready / 'identity.txt']))
        config = {'schema': 1, 'state': str(output), 'project': project, 'port': port,
                  'image': value['image'], 'network_image': value['network_image'],
                  'recipient': str(output / 'recipient.txt')}
        for name in ('domain', 'backup_repository', 'backup_branch'):
            if value[name] is not None:
                config[name] = value[name]
        write(ready / 'service.json', kit.encoded(config))
        write(ready / 'source.json', kit.encoded({'schema': 1, 'sha256': value['sha256'], 'created_at': value['created_at'], 'kit_id': base['kit_id']}))
        kit.require(sync.inventory(root) == before, 'SYNC_PC_CHANGED')
        kit.publish_directory(ready, output)
        return {'action': 'vaultwarden-prepared', 'service': str(output / 'service.json'),
                'sha256': value['sha256'], 'state': 'stopped', 'preferred_url': value['domain'],
                'network': 'authorize this device; retain the preferred address or explicitly choose its replacement'}


def capture(root, service_file, identity, *, replace_sha=None):
    """Privileged service capture, followed by an attachment as the state owner."""
    root, identity = map(kit.outside_git, (root, identity))
    kit.require(root.is_dir() and root.stat().st_mode & 0o077 == 0, 'ECOSYSTEM_OWNER_REQUIRED')
    owner = root.stat()
    kit.require(os.geteuid() in (0, owner.st_uid), 'ECOSYSTEM_OWNER_REQUIRED')
    kit.require(identity.is_file() and identity.stat().st_size <= 4096
                and identity.stat().st_mode & 0o077 == 0, 'VAULT_OPENING_NOT_PRIVATE')
    # Refuse a known conflict before pausing a live service.
    old = kit.safe(root / 'state' / DESIRED)
    selected = descriptor(kit.decode(old.read_bytes())) if old.exists() else None
    kit.require((selected and selected['sha256'] == replace_sha) or (selected is None and replace_sha is None),
                'VAULT_SELECTION_EXISTS_USE_REPLACE_SHA')
    service = vault.Service(service_file)
    receipt = service.backup()
    archive = service.root / 'backups' / receipt['archive']
    if owner.st_uid == os.geteuid():
        return attach(root, archive, identity, receipt, service.config, replace_sha=replace_sha)
    # A root-owned Docker database need not make the user's ecosystem root-owned.
    # Stage just the selected inputs in a private owner directory, then run the
    # normal lock/CAS/retention code with that user's credentials.
    account = pwd.getpwuid(owner.st_uid)
    with tempfile.TemporaryDirectory(prefix='.vault-owner-', dir=root.parent) as temporary:
        work = Path(temporary)
        shutil.copyfile(archive, work / 'native.age')
        write(work / 'identity.txt', identity.read_bytes())
        write(work / 'receipt.json', kit.encoded(receipt))
        write(work / 'service.json', kit.encoded({k: service.config[k] for k in
              ('image', 'network_image', 'domain', 'backup_repository', 'backup_branch') if k in service.config}))
        for path in work.iterdir():
            path.chmod(0o600)
            os.chown(path, owner.st_uid, owner.st_gid)
        os.chown(work, owner.st_uid, owner.st_gid)
        command = ['runuser', '-u', account.pw_name, '--', sys.executable, str(Path(__file__).resolve()),
                   'attach', '--ecosystem', str(root), '--archive', str(work / 'native.age'),
                   '--identity', str(work / 'identity.txt'), '--receipt', str(work / 'receipt.json'),
                   '--service', str(work / 'service.json')]
        if replace_sha is not None:
            command += ['--replace-sha', replace_sha]
        result = subprocess.run(command, capture_output=True, timeout=1800)
        kit.require(result.returncode == 0, 'VAULT_OWNER_ATTACH_FAILED_NATIVE_BACKUP_RETAINED')
        return kit.decode(result.stdout)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    attach_parser = sub.add_parser('attach', help='attach a completed native capture as the ecosystem owner')
    attach_parser.add_argument('--ecosystem', type=Path, required=True)
    attach_parser.add_argument('--archive', type=Path, required=True)
    attach_parser.add_argument('--identity', type=Path, required=True)
    attach_parser.add_argument('--receipt', type=Path, required=True)
    attach_parser.add_argument('--service', type=Path, required=True)
    attach_parser.add_argument('--replace-sha', help='explicitly replace this previous selected capture')
    capture_parser = sub.add_parser('capture', help='capture an existing service and attach as the ecosystem owner')
    capture_parser.add_argument('--ecosystem', type=Path, required=True)
    capture_parser.add_argument('--service', type=Path, required=True)
    capture_parser.add_argument('--identity', type=Path, required=True)
    capture_parser.add_argument('--replace-sha')
    restore_parser = sub.add_parser('restore', help='restore selected state into a new stopped service')
    restore_parser.add_argument('--ecosystem', type=Path, required=True)
    restore_parser.add_argument('--output', type=Path, required=True)
    restore_parser.add_argument('--project', default='frankenstein-vault')
    restore_parser.add_argument('--port', type=int, default=8222)
    args = parser.parse_args(argv)
    if args.action == 'capture':
        result = capture(args.ecosystem, args.service, args.identity, replace_sha=args.replace_sha)
    elif args.action == 'attach':
        result = attach(args.ecosystem, args.archive, args.identity,
                        kit.decode(kit.safe(args.receipt).read_bytes()), kit.decode(kit.safe(args.service).read_bytes()),
                        replace_sha=args.replace_sha)
    else:
        result = restore(args.ecosystem, args.output, project=args.project, port=args.port)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('Vault provisioning failed: ' + str(error), file=sys.stderr)
        sys.exit(2)
