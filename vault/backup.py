"""Private Git backup adapter. Only verified ciphertext and public recovery metadata enter Git."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import recovery_kit as kit
import recovery_opening as opening


def command(args, cwd=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env['GIT_TERMINAL_PROMPT'] = '0'
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    kit.require(result.returncode == 0, 'PRIVATE_BACKUP_PROVIDER_FAILED')
    return result.stdout.strip()


def repository(name):
    kit.require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', name),
                'PRIVATE_REPOSITORY_INVALID')
    value = json.loads(command(['gh', 'api', 'repos/' + name]))
    kit.require(value.get('private') is True and value.get('full_name', '').lower() == name.lower(),
                'PRIVATE_REPOSITORY_REQUIRED')
    branch = value.get('default_branch')
    kit.require(isinstance(branch, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_.-]*', branch),
                'PRIVATE_BRANCH_INVALID')
    return 'https://github.com/' + name + '.git', branch


def publish(repo, candidate, identity, context, capsule, capsule_digest):
    """Validate a stable copy before cloning; preserve all unrelated private repo files."""
    url, branch = repository(repo)
    with tempfile.TemporaryDirectory(prefix='frankenstein-private-backup-') as temporary:
        root = Path(temporary)
        staged = root / 'ciphertext'
        staged.mkdir(mode=0o700)
        shutil.copyfile(kit.safe(candidate), staged / 'vault.age')
        proof = kit.inspect(staged / 'vault.age', identity, context)
        capsule = kit.safe(capsule)
        opening.inspect(capsule, capsule_digest)
        recovery = staged / 'recovery'
        recovery.mkdir(mode=0o700)
        for name in opening.FILES:
            shutil.copyfile(capsule / name, recovery / name)
            (recovery / name).chmod(0o600)
        opening.inspect(recovery, capsule_digest)
        # Prove that THIS emergency key opens THIS backup, not just a separate probe.
        # Native age requests its passphrase on the owner's controlling terminal.
        kit.inspect(staged / 'vault.age', recovery / 'identity.age', context)
        manifest = {'schema': 1, 'ciphertext_sha256': proof['archive_sha256'],
                    'context': kit.context(context), 'recovery_manifest_sha256': capsule_digest}
        (staged / 'backup.json').write_bytes(kit.encoded(manifest))
        checkout = root / 'repository'
        command(['git', 'clone', '--quiet', '--depth=1', '--single-branch', '--branch', branch,
                 '--', url, str(checkout)])
        parent = command(['git', 'rev-parse', 'HEAD'], checkout)
        directory = checkout / 'frankenstein' / 'backups' / proof['archive_sha256']
        kit.safe(directory)
        kit.require(not directory.exists(), 'BACKUP_ALREADY_EXISTS')
        directory.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(staged, directory)
        relative = directory.relative_to(checkout).as_posix()
        # Never git-add the repository wholesale; only the validated new payload.
        command(['git', 'add', '--', relative], checkout)
        command(['git', '-c', 'user.name=Frankenstein backup', '-c',
                 'user.email=frankenstein@localhost', 'commit', '--quiet', '-m',
                 'Back up encrypted Frankenstein state'], checkout)
        # Lease also prevents replacing an intervening device update that was rebased.
        command(['git', 'push', '--porcelain', '--force-with-lease=refs/heads/' + branch + ':' + parent,
                 'origin', 'HEAD:refs/heads/' + branch], checkout)
        return proof['archive_sha256']


def restore(repo, digest, destination):
    """All-device-loss path: GitHub access plus externally held recovery passphrase."""
    url, branch = repository(repo)
    kit.require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'BACKUP_SELECTOR_INVALID')
    destination = kit.outside_git(destination)
    kit.require(not destination.exists(), 'MATERIALIZED_OUTPUT_EXISTS')
    with tempfile.TemporaryDirectory(prefix='frankenstein-private-restore-') as temporary:
        checkout = Path(temporary) / 'repository'
        command(['git', 'clone', '--quiet', '--depth=1', '--single-branch', '--branch', branch,
                 '--', url, str(checkout)])
        source = kit.safe(checkout / 'frankenstein/backups' / digest)
        # Copy ciphertext outside Git before opening; never restore plaintext into a checkout.
        copied = Path(temporary) / 'ciphertext'
        copied.mkdir(mode=0o700)
        expected_files = {'backup.json', 'vault.age', 'recovery/identity.age',
                          'recovery/recipient.txt', 'recovery/manifest.json'}
        kit.require(source.is_dir(), 'BACKUP_MISSING')
        actual = set()
        for path in source.rglob('*'):
            kit.safe(path)
            kit.require(path.is_file() or path.is_dir(), 'BACKUP_FILE_TYPE_INVALID')
            if path.is_file():
                actual.add(path.relative_to(source).as_posix())
        kit.require(actual == expected_files, 'BACKUP_LAYOUT_INVALID')
        for name in sorted(expected_files):
            target = copied / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)
            target.chmod(0o600)
        manifest = kit.decode((copied / 'backup.json').read_bytes())
        kit.require(isinstance(manifest, dict) and set(manifest) ==
                    {'schema', 'ciphertext_sha256', 'context', 'recovery_manifest_sha256'} and
                    type(manifest['schema']) is int and manifest['schema'] == 1 and
                    manifest['ciphertext_sha256'] == digest and kit.sha(copied / 'vault.age') == digest,
                    'BACKUP_INTEGRITY_MISMATCH')
        opening.inspect(copied / 'recovery', manifest['recovery_manifest_sha256'])
        return kit.materialize(copied / 'vault.age', copied / 'recovery/identity.age',
                               manifest['context'], destination, digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True, help='your existing private owner/repo')
    sub = parser.add_subparsers(dest='action', required=True)
    backup = sub.add_parser('publish')
    for name in ('candidate', 'identity', 'context', 'capsule'):
        backup.add_argument('--' + name, type=Path, required=True)
    backup.add_argument('--capsule-sha256', required=True)
    recover = sub.add_parser('restore')
    recover.add_argument('--sha256', required=True)
    recover.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'publish':
            digest = publish(args.repository, args.candidate, args.identity,
                             kit.decode(args.context.read_bytes()), args.capsule, args.capsule_sha256)
            print('PRIVATE_BACKUP=' + digest)
        else:
            restore(args.repository, args.sha256, args.output)
            print('PRIVATE_RESTORE=VERIFIED')
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('PRIVATE_BACKUP=FAIL (' + (str(error) if isinstance(error, kit.KitError)
                                        else type(error).__name__) + ')', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
