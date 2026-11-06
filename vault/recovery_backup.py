"""Restore an Android ciphertext-only backup with an external recovery passphrase."""
import argparse
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import zipfile

import recovery_kit as kit
import recovery_opening as opening

FILES = {'vault.age', 'context.json', 'selection.json',
         'recovery/identity.age', 'recovery/recipient.txt', 'recovery/manifest.json'}
MAX_BACKUP = 8 * 1024**3


def unpack(source, destination):
    # Exact member allowlist; never use extract/extractall on an imported ZIP.
    with zipfile.ZipFile(source) as archive:
        members = archive.infolist()
        kit.require(len(members) == len(FILES) and {item.filename for item in members} == FILES,
                    'RECOVERY_BACKUP_LAYOUT_INVALID')
        kit.require(sum(item.file_size for item in members) <= MAX_BACKUP, 'RECOVERY_BACKUP_TOO_LARGE')
        (destination / 'recovery').mkdir(mode=0o700)
        for item in members:
            maximum = MAX_BACKUP if item.filename == 'vault.age' else 65536
            kit.require(0 < item.file_size <= maximum and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                        'RECOVERY_BACKUP_MEMBER_INVALID')
            path = destination / item.filename
            with path.open('xb') as output:
                path.chmod(0o600)
                with archive.open(item) as stream:
                    remaining = item.file_size
                    while remaining:
                        block = stream.read(min(remaining, 65536))
                        kit.require(bool(block), 'RECOVERY_BACKUP_TRUNCATED')
                        output.write(block)
                        remaining -= len(block)
                    kit.require(not stream.read(1), 'RECOVERY_BACKUP_MEMBER_SIZE_INVALID')
                output.flush()
                os.fsync(output.fileno())
    selection = kit.decode((destination / 'selection.json').read_bytes())
    kit.require(isinstance(selection, dict) and set(selection) == {'schema', 'archive_sha256', 'recovery_manifest_sha256'}
                and type(selection['schema']) is int and selection['schema'] == 1, 'RECOVERY_BACKUP_SELECTION_INVALID')
    for name in ('archive_sha256', 'recovery_manifest_sha256'):
        kit.require(isinstance(selection[name], str) and re.fullmatch('[0-9a-f]{64}', selection[name]),
                    'RECOVERY_BACKUP_HASH_INVALID')
    kit.require(kit.sha(destination / 'vault.age') == selection['archive_sha256'], 'RECOVERY_BACKUP_ARCHIVE_CHANGED')
    capsule = opening.inspect(destination / 'recovery', selection['recovery_manifest_sha256'])
    context = kit.context(kit.decode((destination / 'context.json').read_bytes()))
    return selection, capsule, context


def restore(source, destination, expected):
    source, destination = kit.outside_git(source), kit.outside_git(destination)
    kit.require(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected), 'RECOVERY_BACKUP_SELECTION_REQUIRED')
    kit.require(not destination.exists(), 'RECOVERY_DESTINATION_EXISTS')
    kit.require(source.is_file() and source.stat().st_size <= MAX_BACKUP, 'RECOVERY_BACKUP_TOO_LARGE')
    opening.local_tty()
    kit.private_directories(destination.parent)
    with tempfile.TemporaryDirectory(prefix='.recovery-', dir=destination.parent) as temporary:
        root = Path(temporary)
        selected = root / 'selected.zip'
        shutil.copyfile(source, selected)
        selected.chmod(0o600)
        kit.require(kit.sha(selected) == expected, 'RECOVERY_BACKUP_SELECTION_MISMATCH')
        ready = root / 'ready'
        ready.mkdir(mode=0o700)
        selection, capsule, context = unpack(selected, ready)
        # age owns the passphrase prompt. A successful unlock is used once for
        # this transaction and retained as the restored device's portable key.
        raw = opening.native(['age', '--decrypt', str(ready / 'recovery/identity.age')], interactive=True)
        recipient = opening.native(['age-keygen', '-y'], content=raw).decode().strip()
        kit.require(recipient == capsule['recipient'], 'RECOVERY_IDENTITY_MISMATCH')
        opening.private_write(ready / 'identity.txt', raw)
        del raw
        kit.materialize(ready / 'vault.age', ready / 'identity.txt', context, ready / 'state', selection['archive_sha256'])
        (ready / 'selection.json').unlink()
        kit.sync_directory(ready / 'recovery')
        kit.sync_directory(ready)
        kit.publish_directory(ready, destination)
    return context


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sha256', required=True, help='selected encrypted ZIP digest')
    args = parser.parse_args()
    try:
        restore(args.source, args.output, args.sha256)
        print('RECOVERY_BACKUP=VERIFIED')
    except (OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile) as error:
        print('RECOVERY_BACKUP=FAIL (' + (str(error) if isinstance(error, kit.KitError) else type(error).__name__) + ')', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
