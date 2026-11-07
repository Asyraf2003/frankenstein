"""Provision an age opening identity, optional recovery capsule and verified state.

FPE1 is transport framing, not an encryption format. Its header contains a
portable secret identity. It MUST remain outside Git in private local storage,
travel over authenticated TLS, and be encrypted by the receiving storage owner.
Git backups continue to use backup.py's ciphertext-only layout.
"""
import argparse
import base64
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import tempfile

import recovery_kit as kit
import recovery_opening as opening

MAGIC = b'FPE1'
MAX_HEADER = 65536
MAX_ARCHIVE = 8 * 1024**3 - MAX_HEADER - 8


def create(staging, identity, context, capsule, capsule_digest, destination):
    destination = kit.outside_git(destination)
    identity = kit.outside_git(identity)
    kit.require(identity.is_file() and identity.stat().st_mode & 0o077 == 0
                and identity.stat().st_size <= 4096, 'PORTABLE_IDENTITY_NOT_PRIVATE')
    kit.require((capsule is None) == (capsule_digest is None), 'PORTABLE_RECOVERY_SELECTION_INVALID')
    recovery = opening.inspect(capsule, capsule_digest) if capsule is not None else None
    kit.require(not destination.exists(), 'PORTABLE_DESTINATION_EXISTS')
    kit.private_directories(destination.parent)
    with tempfile.TemporaryDirectory(prefix='.portable-create-', dir=destination.parent) as temporary:
        work = Path(temporary)
        copied_identity = work / 'identity.txt'
        opening.private_write(copied_identity, identity.read_bytes())
        recipient = opening.native(['age-keygen', '-y', str(copied_identity)]).decode().strip()
        archive = work / 'vault.age'
        kit.create(staging, context, [recipient] + ([recovery['recipient']] if recovery else []), archive)
        proof = kit.inspect(archive, copied_identity, context)
        kit.require(archive.stat().st_size <= MAX_ARCHIVE, 'PORTABLE_TOO_LARGE')
        header = {'schema': 1 if recovery else 2, 'identity': copied_identity.read_text(), 'context': kit.context(context),
                  'archive_sha256': proof['archive_sha256'],
                  'recovery_manifest_sha256': capsule_digest,
                  'recovery': {name: base64.b64encode(kit.safe(capsule / name).read_bytes()).decode()
                               for name in sorted(opening.FILES)} if recovery else None}
        # Revalidate the copied recovery capsule; a source change cannot be approved.
        if recovery:
            check = work / 'check-recovery'
            check.mkdir(mode=0o700)
            for name, content in header['recovery'].items():
                opening.private_write(check / name, base64.b64decode(content, validate=True))
            opening.inspect(check, capsule_digest)
        content = kit.encoded(header)
        kit.require(len(content) <= MAX_HEADER, 'PORTABLE_HEADER_TOO_LARGE')
        packed = work / 'bundle'
        with packed.open('xb') as output, archive.open('rb') as source:
            os.fchmod(output.fileno(), 0o600)
            output.write(MAGIC + struct.pack('>I', len(content)) + content)
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        kit.publish_exclusive(packed, destination)
        kit.sync_directory(destination.parent)
    return kit.sha(destination)


def unpack(source, work):
    """Private temporary decoding; nothing is exposed as an accepted installation."""
    source = kit.outside_git(source)
    kit.require(source.is_file() and source.stat().st_size <= MAX_ARCHIVE + MAX_HEADER + 8,
                'PORTABLE_SIZE_INVALID')
    with source.open('rb') as stream:
        kit.require(stream.read(4) == MAGIC, 'PORTABLE_VERSION_INVALID')
        encoded_size = stream.read(4)
        kit.require(len(encoded_size) == 4, 'PORTABLE_HEADER_MISSING')
        size = struct.unpack('>I', encoded_size)[0]
        kit.require(0 < size <= MAX_HEADER, 'PORTABLE_HEADER_TOO_LARGE')
        header = kit.decode(stream.read(size))
        kit.require(isinstance(header, dict) and set(header) == {'schema', 'identity', 'context',
                    'archive_sha256', 'recovery_manifest_sha256', 'recovery'} and
                    type(header['schema']) is int and header['schema'] in (1, 2), 'PORTABLE_HEADER_INVALID')
        kit.context(header['context'])
        kit.require(isinstance(header['identity'], str) and 0 < len(header['identity']) <= 4096,
                    'PORTABLE_IDENTITY_INVALID')
        kit.require(isinstance(header['archive_sha256'], str) and
                    re.fullmatch('[0-9a-f]{64}', header['archive_sha256']), 'PORTABLE_HASH_INVALID')
        if header['schema'] == 1:
            kit.require(isinstance(header['recovery'], dict) and set(header['recovery']) == opening.FILES,
                        'PORTABLE_RECOVERY_INVALID')
            recovery = work / 'recovery'
            recovery.mkdir(mode=0o700)
            for name, content in header['recovery'].items():
                kit.require(isinstance(content, str), 'PORTABLE_RECOVERY_INVALID')
                opening.private_write(recovery / name, base64.b64decode(content, validate=True))
            opening.inspect(recovery, header['recovery_manifest_sha256'])
        else:
            kit.require(header['recovery'] is None and header['recovery_manifest_sha256'] is None,
                        'PORTABLE_RECOVERY_INVALID')
        opening.private_write(work / 'identity.txt', header['identity'].encode())
        with (work / 'vault.age').open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            shutil.copyfileobj(stream, output)
        kit.require(kit.sha(work / 'vault.age') == header['archive_sha256'], 'PORTABLE_ARCHIVE_CHANGED')
        opening.private_write(work / 'context.json', kit.encoded(header['context']))
    return header


def restore(source, destination, expected_bundle):
    destination = kit.outside_git(destination)
    source = kit.outside_git(source)
    kit.require(isinstance(expected_bundle, str) and re.fullmatch('[0-9a-f]{64}', expected_bundle),
                'PORTABLE_SELECTION_REQUIRED')
    kit.require(not destination.exists(), 'MATERIALIZED_OUTPUT_EXISTS')
    kit.private_directories(destination.parent)
    with tempfile.TemporaryDirectory(prefix='.portable-restore-', dir=destination.parent) as temporary:
        root = Path(temporary)
        selected = root / 'selected.bundle'
        shutil.copyfile(kit.safe(source), selected)
        selected.chmod(0o600)
        kit.require(kit.sha(selected) == expected_bundle, 'PORTABLE_SELECTION_MISMATCH')
        ready = root / 'ready'
        ready.mkdir(mode=0o700)
        header = unpack(selected, ready)
        kit.materialize(ready / 'vault.age', ready / 'identity.txt', header['context'],
                        ready / 'state', header['archive_sha256'])
        for path in ready.rglob('*'):
            if path.is_file():
                with path.open('rb') as file:
                    os.fsync(file.fileno())
        if (ready / 'recovery').exists():
            kit.sync_directory(ready / 'recovery')
        kit.sync_directory(ready)
        kit.publish_directory(ready, destination)
    return header['context']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    build = sub.add_parser('create')
    for name in ('staging', 'identity', 'context', 'output'):
        build.add_argument('--' + name, type=Path, required=True)
    build.add_argument('--capsule', type=Path, help='optional independent recovery capsule')
    build.add_argument('--capsule-sha256', help='required when --capsule is supplied')
    recover = sub.add_parser('restore')
    recover.add_argument('--source', type=Path, required=True)
    recover.add_argument('--output', type=Path, required=True)
    recover.add_argument('--sha256', required=True)
    args = parser.parse_args()
    try:
        if args.action == 'create':
            checksum = create(args.staging, args.identity, kit.decode(args.context.read_bytes()),
                              args.capsule, args.capsule_sha256, args.output)
            print('PORTABLE_SHA256=' + checksum)
        else:
            restore(args.source, args.output, args.sha256)
            print('PORTABLE_RESTORE=VERIFIED')
    except (ValueError, OSError, TypeError, KeyError) as error:
        print('PORTABLE=FAIL (' + (str(error) if isinstance(error, kit.KitError) else type(error).__name__) + ')', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
