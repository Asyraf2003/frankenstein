#!/usr/bin/env python3
# Adapted from arch-blueprint 9751624c95cc4011cbc3bad8e46512d70fe0a77b.
# Copyright (c) 2026 Asyraf; upstream MIT license: licenses/upstream-MIT.
"""Enroll an outer age identity encrypted by the recovery passphrase.

Native age owns passphrase entry and encrypted-identity decoding. No password
argument/environment, Vault key reuse, Git output or live owner capture.
"""
import argparse
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

import recovery_kit as kit
from recovery_kit import outside_git

FILES = {'identity.age', 'recipient.txt', 'manifest.json'}
PURPOSE = 'outer-kit-opening-v1'


def native(args, interactive=False, content=None):
    options = {'stdin': subprocess.DEVNULL} if content is None else {'input': content}
    result = subprocess.run(args, **options, stdout=subprocess.PIPE,
                            stderr=None if interactive else subprocess.PIPE)
    kit.require(result.returncode == 0, 'OPENING_NATIVE_FAILED')
    return result.stdout


def local_tty():
    kit.require(sys.stdin.isatty() and sys.stderr.isatty(), 'OPENING_LOCAL_TTY_REQUIRED')


def private_write(path, content):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def challenge(identity, recipient):
    """Prove native opening without exporting the decrypted identity."""
    local_tty()
    with tempfile.TemporaryDirectory(prefix='opening-check-') as temporary:
        root = Path(temporary)
        plaintext, encrypted, restored = (root / n for n in ('challenge', 'challenge.age', 'restored'))
        wanted = os.urandom(64)
        private_write(plaintext, wanted)
        native(['age', '--recipient', recipient, '--output', str(encrypted), str(plaintext)])
        native(['age', '--decrypt', '--identity', str(identity), '--output', str(restored), str(encrypted)],
               interactive=True)
        kit.require(restored.read_bytes() == wanted, 'OPENING_NATIVE_ROUNDTRIP_FAILED')


def inspect(folder, expected_manifest):
    folder = outside_git(folder)
    kit.require(folder.is_dir() and folder.stat().st_uid == os.geteuid()
                and folder.stat().st_mode & 0o077 == 0, 'OPENING_NOT_PRIVATE')
    kit.require(isinstance(expected_manifest, str) and re.fullmatch('[0-9a-f]{64}', expected_manifest),
                'OPENING_EXPECTATION_REQUIRED')
    kit.require({p.name for p in folder.iterdir()} == FILES, 'OPENING_LAYOUT_INVALID')
    for name in FILES:
        path = kit.safe(folder / name)
        info = path.stat()
        kit.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_mode & 0o077 == 0 and 0 < info.st_size <= 65536, 'OPENING_FILE_INVALID')
    manifest = folder / 'manifest.json'
    kit.require(manifest.stat().st_size <= 4096 and kit.sha(manifest) == expected_manifest,
                'OPENING_SELECTION_MISMATCH')
    value = kit.decode(manifest.read_bytes())
    kit.require(isinstance(value, dict) and set(value) ==
                {'schema', 'purpose', 'recipient', 'identity_sha256', 'recipient_sha256'}
                and type(value['schema']) is int and value['schema'] == 1 and value['purpose'] == PURPOSE,
                'OPENING_MANIFEST_INVALID')
    recipient = value['recipient']
    kit.require(isinstance(recipient, str) and re.fullmatch('age1[0-9a-z]{58}', recipient),
                'OPENING_RECIPIENT_INVALID')
    kit.require((folder / 'recipient.txt').read_bytes() == (recipient + '\n').encode()
                and kit.sha(folder / 'recipient.txt') == value['recipient_sha256']
                and kit.sha(folder / 'identity.age') == value['identity_sha256'], 'OPENING_HASH_MISMATCH')
    kit.require((folder / 'identity.age').read_bytes().startswith(b'age-encryption.org/v1\n-> scrypt '),
                'OPENING_ENCRYPTED_IDENTITY_REQUIRED')
    return value


def verify(folder, expected_manifest):
    value = inspect(folder, expected_manifest)
    challenge(kit.safe(folder) / 'identity.age', value['recipient'])
    kit.require(inspect(folder, expected_manifest) == value, 'OPENING_CHANGED_DURING_CHECK')
    return value


def enroll(destination):
    destination = outside_git(destination)
    kit.require(not destination.exists(), 'OPENING_DESTINATION_EXISTS')
    local_tty()
    print('Keep your recovery passphrase outside this vault and outside these devices.\n'
          'Keep a backup of the encrypted identity.age, recipient.txt and manifest.json.\n'
          'The passphrase alone cannot replace a lost encrypted recovery identity.', flush=True)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Reserve exclusively; never overwrite or adopt another enrollment.
    destination.mkdir(mode=0o700)
    reserved = destination.stat()
    try:
        with tempfile.TemporaryDirectory(prefix='.opening-enroll-', dir=destination.parent) as temporary:
            root = Path(temporary)
            wrapped = root / 'identity.age'
            # Native key bytes travel only through memory/stdin pipes. Even a
            # killed enrollment leaves no plaintext opening-key file behind.
            raw = native(['age-keygen'])
            recipient = native(['age-keygen', '-y'], content=raw).decode().strip()
            kit.require(re.fullmatch('age1[0-9a-z]{58}', recipient), 'OPENING_RECIPIENT_INVALID')
            # The operator enters/holds the fourth emergency anchor locally.
            # No wrapper reads it, and native age never receives it via argv/env.
            native(['age', '--passphrase', '--output', str(wrapped)], interactive=True, content=raw)
            wrapped.chmod(0o600)
            del raw
            # Only the wrapped key remains when proving it can open ciphertext.
            challenge(wrapped, recipient)
            with wrapped.open('rb') as stream:
                os.fsync(stream.fileno())
            os.link(wrapped, destination / 'identity.age')
            private_write(destination / 'recipient.txt', (recipient + '\n').encode())
            value = {'schema': 1, 'purpose': PURPOSE, 'recipient': recipient,
                     'identity_sha256': kit.sha(wrapped),
                     'recipient_sha256': kit.sha(destination / 'recipient.txt')}
            private_write(destination / 'manifest.json', kit.encoded(value))
            kit.sync_directory(destination)
            kit.sync_directory(destination.parent)
            checksum = kit.sha(destination / 'manifest.json')
            inspect(destination, checksum)
        return checksum
    except BaseException:
        # Cleanup only our reserved inode, preserving a replaced/preexisting path.
        if destination.exists() and not destination.is_symlink():
            current = destination.stat()
            if (current.st_dev, current.st_ino) == (reserved.st_dev, reserved.st_ino):
                shutil.rmtree(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('enroll', 'verify', 'recipient'))
    parser.add_argument('--opening', type=Path, required=True)
    parser.add_argument('--expected-manifest')
    args = parser.parse_args()
    try:
        if args.action == 'enroll':
            kit.require(args.expected_manifest is None, 'OPENING_ENROLL_EXPECTATION_INVALID')
            checksum = enroll(args.opening)
            print('OUTER_OPENING=ENROLLED\nMANIFEST_SHA256=' + checksum)
        elif args.action == 'verify':
            verify(args.opening, args.expected_manifest)
            print('OUTER_OPENING=VERIFIED')
        else:
            print(inspect(args.opening, args.expected_manifest)['recipient'])
    except KeyboardInterrupt:
        print('OUTER_OPENING=INTERRUPTED; values withheld', file=sys.stderr)
        return 130
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        tag = str(error) if isinstance(error, kit.KitError) else type(error).__name__
        print('OUTER_OPENING=FAIL (' + tag + '); values withheld', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
