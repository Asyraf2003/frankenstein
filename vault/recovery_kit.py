#!/usr/bin/env python3
# Adapted from arch-blueprint 9751624c95cc4011cbc3bad8e46512d70fe0a77b.
# Copyright (c) 2026 Asyraf; upstream MIT license: licenses/upstream-MIT.
"""Native tar/age envelope for explicitly staged owner outputs.

Format validation does not certify live snapshots or workstation readiness.
Native Vault/keyring consumers keep ownership of their internal formats.
"""
import argparse
import ctypes
import errno
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid

OWNERS = {'credentials', 'recovery', 'keyring', 'vault', 'projects', 'desired'}
REPOSITORIES = {'engine', 'state'}


class KitError(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise KitError(code)


def safe(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'PATH_CONFLICT')
    return path


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private_directories(path):
    """mkdir -p with 0700 for every newly created parent, regardless of umask."""
    path = safe(path)
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    require(path.is_dir(), 'PATH_CONFLICT')
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)


def publish_exclusive(source, destination):
    """Exclusive private publication; Android Python may omit hard links."""
    link = getattr(os, 'link', None)
    if link is not None:
        return link(source, destination)
    reserved = None
    try:
        with destination.open('xb') as target:
            os.fchmod(target.fileno(), 0o600)
            reserved = os.fstat(target.fileno())
            with source.open('rb') as stream:
                shutil.copyfileobj(stream, target)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        if reserved is not None:
            try:
                now = destination.lstat()
                if (now.st_dev, now.st_ino) == (reserved.st_dev, reserved.st_ino):
                    destination.unlink()
            except FileNotFoundError:
                pass
        raise


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def decode(content):
    return json.loads(content, object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def context(value):
    require(isinstance(value, dict) and set(value) ==
            {'revisions', 'features', 'required_owners'}, 'CONTEXT_INVALID')
    revisions = value['revisions']
    require(isinstance(revisions, dict) and set(revisions) == REPOSITORIES and
            all(isinstance(v, str) and re.fullmatch('[0-9a-f]{40}', v)
                for v in revisions.values()), 'REVISIONS_INVALID')
    features = value['features']
    require(isinstance(features, list) and all(isinstance(v, str) and 0 < len(v) <= 128
            for v in features) and len(features) == len(set(features)), 'FEATURES_INVALID')
    owners = value['required_owners']
    require(isinstance(owners, list) and bool(owners) and
            all(isinstance(v, str) and v in OWNERS for v in owners) and
            len(owners) == len(set(owners)), 'REQUIRED_OWNERS_INVALID')
    return {'revisions': dict(revisions), 'features': sorted(features),
            'required_owners': sorted(owners)}


def outside_git(path):
    path = safe(path).resolve()
    # A linked worktree may have a Windows-form gitdir pointer when accessed
    # from WSL. Never interpret git's inability to resolve it as a safe output.
    require(not any((parent / '.git').exists() for parent in (path, *path.parents)),
            'OUTPUTS_MUST_BE_OUTSIDE_GIT')
    # Refuse ordinary repositories, linked worktrees and bare repositories.
    existing = path if path.is_dir() else path.parent
    while not existing.exists():
        existing = existing.parent
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    result = subprocess.run(['git', '-C', str(existing), 'rev-parse',
                             '--is-inside-work-tree', '--is-inside-git-dir'],
                            capture_output=True, timeout=30, env=env)
    require(result.returncode != 0 or b'true' not in result.stdout.splitlines(),
            'OUTPUTS_MUST_BE_OUTSIDE_GIT')
    return path


def artifact_name(name):
    require(isinstance(name, str) and not any(c in name for c in '\x00\r\n\\'), 'ARTIFACT_PATH_INVALID')
    path = PurePosixPath(name)
    require(not path.is_absolute() and len(path.parts) >= 2 and
            '..' not in path.parts and path.as_posix() == name and
            path.parts[0] in OWNERS, 'ARTIFACT_PATH_INVALID')
    return path.parts[0]


def manifest(value):
    require(isinstance(value, dict) and set(value) ==
            {'schema', 'kit_id', 'created_at', 'context', 'files'} and
            type(value['schema']) is int and value['schema'] == 1, 'MANIFEST_INVALID')
    require(isinstance(value['kit_id'], str) and re.fullmatch('[0-9a-f]{32}', value['kit_id']), 'KIT_ID_INVALID')
    require(isinstance(value['created_at'], str) and bool(value['created_at']), 'TIMESTAMP_INVALID')
    ctx = context(value['context'])
    files = value['files']
    require(isinstance(files, dict) and bool(files), 'FILES_MISSING')
    present = set()
    for name, entry in files.items():
        owner = artifact_name(name)
        require(isinstance(entry, dict) and set(entry) == {'owner', 'size', 'sha256'} and
                entry['owner'] == owner and type(entry['size']) is int and entry['size'] >= 0 and
                isinstance(entry['sha256'], str) and re.fullmatch('[0-9a-f]{64}', entry['sha256']),
                'FILE_RECORD_INVALID')
        present.add(owner)
    require(set(ctx['required_owners']) <= present, 'REQUIRED_OWNER_MISSING')
    return value


def native(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    require(result.returncode == 0, 'AGE_OPERATION_FAILED')


def stable(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def inventory(staging):
    # Owner adapters must provide immutable staging. These checks also catch
    # ordinary concurrent changes; they are not a live database snapshot owner.
    roots = list(staging.iterdir())
    require(all(p.name in OWNERS and not p.is_symlink() and p.is_dir()
                for p in roots), 'STAGING_OWNER_INVALID')
    entries = {}
    for path in [staging, *sorted(staging.rglob('*'))]:
        safe(path)
        info = path.stat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'ARTIFACT_TYPE_INVALID')
        entries[path.relative_to(staging).as_posix()] = stable(info)
    return entries


def build(staging, ctx, archive):
    staging = safe(staging)
    require(staging.is_dir(), 'STAGING_MISSING')
    # Only named owner staging trees; never recursively back up an arbitrary home.
    before = inventory(staging)
    files = {}
    value = {'schema': 1, 'kit_id': uuid.uuid4().hex,
             'created_at': datetime.now(timezone.utc).isoformat(),
             'context': context(ctx), 'files': files}
    archive.touch(mode=0o600, exist_ok=False)
    with tarfile.open(archive, 'w') as output:
        for name in sorted(before):
            path = safe(staging / name)
            info = path.stat()
            require(stable(info) == before[name], 'STAGING_CHANGED')
            if stat.S_ISDIR(info.st_mode):
                continue
            owner = artifact_name(name)
            record = {'owner': owner, 'size': info.st_size, 'sha256': sha(path)}
            header = tarfile.TarInfo('payload/' + name)
            header.size, header.mode = info.st_size, 0o600
            with path.open('rb') as stream:
                output.addfile(header, stream)
            require(stable(info) == stable(path.stat()), 'STAGING_CHANGED')
            files[name] = record
        require(inventory(staging) == before, 'STAGING_CHANGED')
        manifest(value)
        content = encoded(value)
        require(len(content) <= 1024 * 1024, 'MANIFEST_TOO_LARGE')
        header = tarfile.TarInfo('manifest.json')
        header.size, header.mode = len(content), 0o600
        output.addfile(header, io.BytesIO(content))
    return value


def create(staging, ctx, recipients, candidate):
    require(bool(recipients) and all(isinstance(v, str) and v for v in recipients), 'RECIPIENTS_MISSING')
    candidate = safe(candidate)
    require(not candidate.exists(), 'CANDIDATE_EXISTS')
    staging = safe(staging)
    require(not candidate.is_relative_to(staging), 'STAGING_OUTPUT_OVERLAP')
    candidate.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix='.kit-create-', dir=candidate.parent) as folder:
        folder = Path(folder)
        value = build(staging, ctx, folder / 'payload.tar')
        args = ['age']
        for recipient in recipients:
            args += ['--recipient', recipient]
        encrypted = folder / 'candidate.age'
        native([*args, '--output', str(encrypted), str(folder / 'payload.tar')])
        encrypted.chmod(0o600)
        with encrypted.open('rb') as stream:
            os.fsync(stream.fileno())
        # Exclusive native publication: preserve an existing candidate, including a race.
        publish_exclusive(encrypted, candidate)
        sync_directory(candidate.parent)
    return value


def inspect(candidate, identity, expected, *, _materialize=None):
    candidate, identity = safe(candidate), safe(identity)
    expected = context(expected)
    with tempfile.TemporaryDirectory(prefix='.kit-inspect-') as folder:
        copied = Path(folder) / 'candidate.age'
        require(candidate.is_file(), 'CANDIDATE_MISSING')
        before = stable(candidate.stat())
        shutil.copyfile(candidate, copied)
        copied.chmod(0o600)
        require(stable(candidate.stat()) == before, 'CANDIDATE_CHANGED')
        digest = sha(copied)
        archive = Path(folder) / 'payload.tar'
        # age can emit a valid plaintext prefix before failing at the end.
        # Its FINAL exit status gates every tar/manifest operation below.
        native(['age', '--decrypt', '--identity', str(identity), '--output', str(archive), str(copied)])
        with tarfile.open(archive, 'r:') as source:
            members = source.getmembers()
            names = [m.name for m in members]
            require(len(names) == len(set(names)) and all(m.isfile() for m in members), 'ARCHIVE_TYPE_OR_DUPLICATE')
            require('manifest.json' in names, 'MANIFEST_MISSING')
            require(source.getmember('manifest.json').size <= 1024 * 1024, 'MANIFEST_TOO_LARGE')
            value = manifest(decode(source.extractfile('manifest.json').read()))
            require(context(value['context']) == expected, 'CONTEXT_MISMATCH')
            require(set(names) == {'manifest.json', *('payload/' + n for n in value['files'])}, 'ARCHIVE_LAYOUT_INVALID')
            for name, record in value['files'].items():
                member = source.getmember('payload/' + name)
                require(member.size == record['size'], 'ARTIFACT_SIZE_MISMATCH')
                with source.extractfile(member) as stream:
                    file_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                require(file_digest == record['sha256'], 'ARTIFACT_HASH_MISMATCH')
            if _materialize is not None:
                # The final age status and complete tar/context/hash validation
                # above gate every write. Never call tar.extract/extractall.
                for name, record in value['files'].items():
                    destination = safe(_materialize / name)
                    private_directories(destination.parent)
                    with destination.open('xb') as target, source.extractfile('payload/' + name) as stream:
                        os.fchmod(target.fileno(), 0o600)
                        shutil.copyfileobj(stream, target)
                        target.flush()
                        os.fsync(target.fileno())
                    require(sha(destination) == record['sha256'], 'ARTIFACT_HASH_MISMATCH')
        return {'manifest': value, 'archive_sha256': digest}


def materialize(candidate, identity, expected, destination, expected_archive):
    """Selected verified owner files, privately outside Git; never overwrite."""
    destination = outside_git(destination)
    require(not destination.exists(), 'MATERIALIZED_OUTPUT_EXISTS')
    require(isinstance(expected_archive, str) and re.fullmatch('[0-9a-f]{64}', expected_archive),
            'ARCHIVE_EXPECTATION_REQUIRED')
    private_directories(destination.parent)
    with tempfile.TemporaryDirectory(prefix='.kit-materialize-', dir=destination.parent) as temporary:
        files = Path(temporary) / 'owners'
        files.mkdir(mode=0o700)
        proof = inspect(candidate, identity, expected, _materialize=files)
        require(proof['archive_sha256'] == expected_archive, 'ARCHIVE_SELECTION_MISMATCH')
        for directory in sorted((p for p in files.rglob('*') if p.is_dir()),
                                key=lambda p: len(p.parts), reverse=True):
            sync_directory(directory)
        sync_directory(files)
        # Linux/Android native atomic exclusive rename: a concurrent empty
        # destination must not be overwritten either. Fail closed if unavailable.
        publish_directory(files, destination)
    return proof


def publish_directory(source, destination):
    """Publish a fully verified private directory without replacing any target."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    require(rename is not None, 'ATOMIC_RESTORE_UNAVAILABLE')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise KitError('MATERIALIZED_OUTPUT_EXISTS')
        raise OSError(code, 'atomic restore publication failed')
    sync_directory(destination.parent)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def current(store):
    latest = safe(store / 'latest.json')
    if not latest.exists():
        return None
    receipt = decode(latest.read_bytes())
    require(isinstance(receipt, dict) and set(receipt) ==
            {'schema', 'kit_id', 'archive', 'archive_sha256'} and
            type(receipt['schema']) is int and receipt['schema'] == 1,
            'CURRENT_DRIFT')
    require(isinstance(receipt['kit_id'], str) and re.fullmatch('[0-9a-f]{32}', receipt['kit_id']) and
            receipt['archive'] == 'kit-' + receipt['kit_id'] + '.age', 'CURRENT_DRIFT')
    archive = safe(store / receipt['archive'])
    require(archive.is_file() and sha(archive) == receipt['archive_sha256'], 'CURRENT_DRIFT')
    return receipt


@contextmanager
def writer(store):
    safe(store)
    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(store.stat().st_uid == os.geteuid() and store.stat().st_mode & 0o077 == 0, 'STORE_NOT_PRIVATE')
    path = safe(store / 'recovery-kit.lock')
    with path.open('a+b') as lock:
        os.fchmod(lock.fileno(), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise KitError('STORE_BUSY') from None
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def promote(candidate, identity, store, expected):
    candidate, store = safe(candidate), safe(store)
    with writer(store):
        current(store)  # Refuse drift before touching the current generation.
        proof = inspect(candidate, identity, expected)
        identifier = proof['manifest']['kit_id']
        filename = 'kit-' + identifier + '.age'
        archive = safe(store / filename)
        if archive.exists():
            require(sha(archive) == proof['archive_sha256'], 'VERSION_CONFLICT')
        else:
            with tempfile.TemporaryDirectory(prefix='.kit-copy-', dir=store) as folder:
                copied = Path(folder) / 'candidate.age'
                shutil.copyfile(candidate, copied)
                copied.chmod(0o600)
                require(sha(copied) == proof['archive_sha256'], 'CANDIDATE_CHANGED')
                with copied.open('rb') as stream:
                    os.fsync(stream.fileno())
                publish_exclusive(copied, archive)
            sync_directory(store)
        receipt = {'schema': 1, 'kit_id': identifier, 'archive': filename,
                   'archive_sha256': proof['archive_sha256']}
        fd, name = tempfile.mkstemp(prefix='.latest-', dir=store)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encoded(receipt))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, store / 'latest.json')
            sync_directory(store)
        finally:
            Path(name).unlink(missing_ok=True)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    pack = commands.add_parser('create')
    pack.add_argument('--staging', type=Path, required=True)
    pack.add_argument('--context', type=Path, required=True)
    pack.add_argument('--recipient', action='append', required=True)
    pack.add_argument('--output', type=Path, required=True)
    check = commands.add_parser('inspect')
    check.add_argument('--candidate', type=Path, required=True)
    check.add_argument('--identity', type=Path, required=True)
    check.add_argument('--context', type=Path, required=True)
    accept = commands.add_parser('promote')
    accept.add_argument('--candidate', type=Path, required=True)
    accept.add_argument('--identity', type=Path, required=True)
    accept.add_argument('--store', type=Path, required=True)
    accept.add_argument('--context', type=Path, required=True)
    restore = commands.add_parser('restore')
    restore.add_argument('--candidate', type=Path, required=True)
    restore.add_argument('--identity', type=Path, required=True)
    restore.add_argument('--context', type=Path, required=True)
    restore.add_argument('--output', type=Path, required=True)
    restore.add_argument('--sha256', required=True, help='selected ciphertext digest')
    args = parser.parse_args()
    try:
        if args.command == 'create':
            create(args.staging, decode(safe(args.context).read_bytes()), args.recipient, args.output)
            print('KIT_CANDIDATE=CREATED (format/owner readiness not yet proven)')
        elif args.command == 'inspect':
            proof = inspect(args.candidate, args.identity, decode(safe(args.context).read_bytes()))
            print('KIT_FORMAT=VALID files=' + str(len(proof['manifest']['files'])))
        elif args.command == 'restore':
            materialize(args.candidate, args.identity, decode(safe(args.context).read_bytes()),
                        args.output, args.sha256)
            print('KIT_RESTORE=VERIFIED (staged files; system application remains separate)')
        else:
            promote(args.candidate, args.identity, args.store, decode(safe(args.context).read_bytes()))
            print('KIT_FORMAT_PROMOTION=PASS (native owner readiness remains separate)')
    except (OSError, ValueError, tarfile.TarError, KeyError, TypeError) as error:
        tag = str(error) if isinstance(error, KitError) else type(error).__name__
        print('RECOVERY_KIT=FAIL (' + tag + ')', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
