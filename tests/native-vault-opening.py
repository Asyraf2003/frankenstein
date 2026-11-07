#!/usr/bin/env python3
"""Disposable native age/TTY encrypted-identity proof; no real input or device."""
import errno
import json
import os
from pathlib import Path
import pty
import secrets
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import termios
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vault'))
import recovery_kit as kit
import recovery_opening as opening
import backup

SCRIPT = ROOT / 'vault/recovery_opening.py'


def tty(args, answers, timeout=40, native=False):
    """Feed dummy native /dev/tty prompts, never argv/env or printed transcripts."""
    pid, descriptor = pty.fork()
    if pid == 0:
        if native:
            os.execvp(str(args[0]), list(map(str, args)))
        os.execv(sys.executable, [sys.executable, '-B', *map(str, args)])
    output, supplied, scanned, pending = bytearray(), 0, 0, False
    deadline = time.monotonic() + timeout
    status = None
    try:
        while time.monotonic() < deadline:
            if select.select([descriptor], [], [], 0.03)[0]:
                try:
                    block = os.read(descriptor, 65536)
                    if not block:
                        break
                    output.extend(block)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                lower = bytes(output).lower()
                # Native age uses Enter/Confirm passphrase, including -i keys.
                triggers = [lower.find(word, scanned) for word in
                            (b'enter passphrase', b'confirm passphrase')]
                found = [position for position in triggers if position >= 0]
                if found:
                    scanned = min(found) + 10
                    pending = True
            # Wait until native terminal echo is disabled before dummy entry.
            if pending and not termios.tcgetattr(descriptor)[3] & termios.ECHO:
                if supplied >= len(answers):
                    raise AssertionError('unexpected native passphrase prompt; transcript withheld')
                os.write(descriptor, answers[supplied].encode() + b'\n')
                supplied += 1
                pending = False
        else:
            raise AssertionError('native TTY command timed out; transcript withheld')
        _, status = os.waitpid(pid, 0)
    finally:
        os.close(descriptor)
        if status is None:
            try:
                if os.getpgid(pid) == pid:
                    os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
    for value in answers:
        if value.encode() in output:
            raise AssertionError('dummy secret echoed; transcript withheld')
    if b'AGE-SECRET-KEY-' in output:
        raise AssertionError('plaintext identity emitted; transcript withheld')
    return os.waitstatus_to_exitcode(status), bytes(output), supplied


class NativeOpening(unittest.TestCase):
    def test_backup_rejects_public_repository_before_reading_secrets(self):
        with patch.object(backup, 'command', return_value=json.dumps({
                'private': False, 'full_name': 'example/state', 'default_branch': 'main'})):
            with self.assertRaisesRegex(kit.KitError, 'PRIVATE_REPOSITORY_REQUIRED'):
                backup.publish('example/state', None, None, None, None, None)

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='native-opening-proof-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.secret = secrets.token_urlsafe(24)
        cls.original = cls.root / 'original'
        code, output, supplied = tty([SCRIPT, 'enroll', '--opening', cls.original], [cls.secret] * 3)
        if code or b'OUTER_OPENING=ENROLLED' not in output or supplied != 3:
            raise AssertionError('native enrollment failed; transcript withheld')
        cls.expected = kit.sha(cls.original / 'manifest.json')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='case-', dir=self.root)
        self.addCleanup(temporary.cleanup)
        self.case = Path(temporary.name)
        self.folder = self.case / 'opening'
        shutil.copytree(self.original, self.folder)

    def test_native_encrypted_identity_opens_existing_d1_promotion(self):
        value = opening.inspect(self.folder, self.expected)
        self.assertEqual({p.name for p in self.folder.iterdir()}, opening.FILES)
        self.assertTrue(all(p.stat().st_mode & 0o077 == 0 for p in self.folder.iterdir()))
        stage = self.case / 'staging'
        (stage / 'projects').mkdir(parents=True, mode=0o700)
        (stage / 'projects/dummy.txt').write_text('dummy envelope seam only\n')
        ctx = {'revisions': {'engine': '1' * 40, 'state': '2' * 40},
               'features': ['projects'], 'required_owners': ['projects']}
        candidate = self.case / 'candidate.age'
        kit.create(stage, ctx, [value['recipient']], candidate)
        context_file = self.case / 'context.json'
        context_file.write_bytes(kit.encoded(ctx))
        driver = ('import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
                  'import recovery_kit as kit;'
                  'kit.promote(Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]),'
                  'json.loads(Path(sys.argv[5]).read_text()));print("D1_CAPSULE_PROMOTE=PASS")')
        code, output, supplied = tty(['-c', driver, ROOT / 'vault', candidate,
                                     self.folder / 'identity.age', self.case / 'store', context_file],
                                    [self.secret])
        self.assertEqual(code, 0, 'D1 native encrypted-identity seam failed; transcript withheld')
        self.assertEqual(supplied, 1)
        self.assertIn(b'D1_CAPSULE_PROMOTE=PASS', output)
        receipt = kit.current(self.case / 'store')
        self.assertIsNotNone(receipt)
        latest = (self.case / 'store/latest.json').read_bytes()
        archive = self.case / 'store' / receipt['archive']
        previous = archive.read_bytes()
        wrong = secrets.token_urlsafe(24)
        code, _, _ = tty(['-c', driver, ROOT / 'vault', candidate,
                           self.folder / 'identity.age', self.case / 'store', context_file], [wrong] * 3)
        self.assertNotEqual(code, 0)
        self.assertEqual((self.case / 'store/latest.json').read_bytes(), latest)
        self.assertEqual(archive.read_bytes(), previous)
        restored = self.case / 'restored-with-emergency-key'
        # Delete the producer payload: restore must use only ciphertext, wrapped
        # recovery identity, expected context/digest and the external passphrase.
        shutil.rmtree(stage)
        code, output, supplied = tty([ROOT / 'vault/recovery_kit.py', 'restore',
            '--candidate', archive, '--identity', self.folder / 'identity.age',
            '--context', context_file, '--output', restored, '--sha256', kit.sha(archive)],
            [self.secret])
        self.assertEqual(code, 0, 'emergency restore failed; transcript withheld')
        self.assertEqual(supplied, 1)
        self.assertIn(b'KIT_RESTORE=VERIFIED', output)
        self.assertEqual((restored / 'projects/dummy.txt').read_text(), 'dummy envelope seam only\n')
        # Real Git transport against a disposable bare remote. GitHub metadata is
        # the only substituted boundary; encryption, commits, push and restore are native.
        remote = self.case / 'remote.git'
        seed = self.case / 'seed'
        def git(*args):
            subprocess.run(['git', *map(str, args)], check=True, capture_output=True)
        git('init', '--bare', '--initial-branch=main', remote)
        git('clone', remote, seed)
        (seed / 'unrelated.txt').write_text('preserve existing user state')
        git('-C', seed, 'add', 'unrelated.txt')
        git('-C', seed, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@localhost',
            'commit', '-m', 'fixture')
        git('-C', seed, 'push', 'origin', 'main')
        driver = ('import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
                  'import backup;backup.repository=lambda name,branch=None:(sys.argv[2],"main");'
                  'digest=backup.publish("fixture/state",Path(sys.argv[3]),Path(sys.argv[4]),'
                  'json.loads(Path(sys.argv[5]).read_text()),Path(sys.argv[6]),sys.argv[7]);'
                  'backup.restore("fixture/state",digest,Path(sys.argv[8]));print("GIT_RECOVERY=PASS")')
        git_restored = self.case / 'git-restored'
        code, output, supplied = tty(['-c', driver, ROOT / 'vault', remote, archive,
            self.folder / 'identity.age', context_file, self.folder, self.expected, git_restored],
            [self.secret] * 3)
        self.assertEqual(code, 0, 'native Git recovery failed; transcript withheld')
        self.assertEqual(supplied, 3)
        self.assertIn(b'GIT_RECOVERY=PASS', output)
        self.assertEqual((git_restored / 'projects/dummy.txt').read_text(), 'dummy envelope seam only\n')
        git('-C', seed, 'pull', '--ff-only')
        self.assertEqual((seed / 'unrelated.txt').read_text(), 'preserve existing user state')
        sparse = self.case / 'sparse-read'
        backup.checkout_backup(str(remote), 'main', sparse)
        self.assertFalse((sparse / 'unrelated.txt').exists())
        self.assertTrue((sparse / 'frankenstein/backups').is_dir())
        self.assertEqual({p.name for p in sparse.iterdir()}, {'.git', 'frankenstein'})
        for path in (seed / 'frankenstein').rglob('*'):
            if path.is_file():
                self.assertNotIn(b'AGE-SECRET-KEY-', path.read_bytes())
                self.assertNotIn(b'dummy envelope seam only', path.read_bytes())
        local_identity = self.case / 'device-key.txt'
        subprocess.run(['age-keygen', '--output', str(local_identity)], check=True, capture_output=True)
        routine = ('import sys,json;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
                   'import backup;backup.repository=lambda name,branch=None:(sys.argv[2],"main");'
                   'print(backup.capture("fixture/state",Path(sys.argv[3]),Path(sys.argv[4]),'
                   'json.loads(Path(sys.argv[5]).read_text()),Path(sys.argv[6]),sys.argv[7]))')
        result = subprocess.run([sys.executable, '-c', routine, str(ROOT / 'vault'), str(remote),
            str(git_restored), str(local_identity), str(context_file), str(self.folder), self.expected],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, start_new_session=True, timeout=30)
        self.assertEqual(result.returncode, 0, 'unattended capture failed; transcript withheld')
        digest = result.stdout.strip()
        self.assertRegex(digest, r'^[0-9a-f]{64}$')
        race = '''import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import backup
import recovery_kit as kit
backup.repository=lambda name,branch=None:(sys.argv[2],"main")
original=backup.command
competing=[]
def command(args,cwd=None):
    if args[:2]==['git','push']:
        seed=Path(sys.argv[8])
        original(['git','pull','--ff-only'],seed)
        (seed/'other-device.txt').write_text('concurrent device tuning')
        original(['git','add','other-device.txt'],seed)
        original(['git','-c','user.name=Fixture','-c','user.email=fixture@localhost',
                  'commit','-m','concurrent update'],seed)
        original(['git','push','origin','main'],seed)
        competing.append(original(['git','rev-parse','HEAD'],seed))
    return original(args,cwd)
backup.command=command
try:
    backup.capture('fixture/state',Path(sys.argv[3]),Path(sys.argv[4]),
                   json.loads(Path(sys.argv[5]).read_text()),Path(sys.argv[6]),sys.argv[7])
except kit.KitError:
    assert competing and original(['git','--git-dir',sys.argv[2],'rev-parse','main'])==competing[0]
    print('CONCURRENT_UPDATE_PRESERVED')
else:
    raise AssertionError('concurrent update was silently replaced')
'''
        result = subprocess.run([sys.executable, '-c', race, str(ROOT / 'vault'), str(remote),
            str(git_restored), str(local_identity), str(context_file), str(self.folder), self.expected, str(seed)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, start_new_session=True, timeout=30)
        self.assertEqual(result.returncode, 0, 'concurrent push test failed; transcript withheld')
        self.assertIn('CONCURRENT_UPDATE_PRESERVED', result.stdout)
        # Remove the device key. Only the independently wrapped recovery key remains.
        local_identity.unlink()
        recovered_again = self.case / 'routine-backup-recovered'
        recover = ('import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);'
                   'import backup;backup.repository=lambda name,branch=None:(sys.argv[2],"main");'
                   'backup.restore("fixture/state",sys.argv[3],Path(sys.argv[4]));print("RECOVERED")')
        code, output, supplied = tty(['-c', recover, ROOT / 'vault', remote, digest, recovered_again],
                                    [self.secret])
        self.assertEqual(code, 0, 'unattended backup recovery failed; transcript withheld')
        self.assertEqual(supplied, 1)
        self.assertEqual((recovered_again / 'projects/dummy.txt').read_text(), 'dummy envelope seam only\n')

    def test_copy_uses_native_verify_and_public_recipient_without_secret_entry(self):
        code, output, _ = tty([SCRIPT, 'verify', '--opening', self.folder,
                               '--expected-manifest', self.expected], [self.secret])
        self.assertEqual(code, 0, 'native copied-key verification failed; transcript withheld')
        self.assertIn(b'OUTER_OPENING=VERIFIED', output)
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), 'recipient', '--opening',
                                 str(self.folder), '--expected-manifest', self.expected],
                                stdin=subprocess.DEVNULL, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, (self.folder / 'recipient.txt').read_bytes())

    def test_wrong_passphrase_preserves_existing_capsule(self):
        before = {p.name: p.read_bytes() for p in self.folder.iterdir()}
        wrong = secrets.token_urlsafe(24)
        code, output, _ = tty([SCRIPT, 'verify', '--opening', self.folder,
                               '--expected-manifest', self.expected], [wrong] * 3)
        self.assertNotEqual(code, 0)
        self.assertIn(b'OUTER_OPENING=FAIL', output)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.folder.iterdir()})

    def test_independent_selection_and_received_file_changes_are_rejected(self):
        with self.assertRaisesRegex(kit.KitError, 'OPENING_SELECTION_MISMATCH'):
            opening.inspect(self.folder, '0' * 64)
        recipient = self.folder / 'recipient.txt'
        original = recipient.read_bytes()
        recipient.write_bytes(b'changed public recipient\n')
        with self.assertRaisesRegex(kit.KitError, 'OPENING_HASH_MISMATCH'):
            opening.inspect(self.folder, self.expected)
        recipient.write_bytes(original)
        identity = self.folder / 'identity.age'
        identity.write_bytes(identity.read_bytes()[:-1])
        with self.assertRaisesRegex(kit.KitError, 'OPENING_HASH_MISMATCH'):
            opening.inspect(self.folder, self.expected)

    def test_existing_git_symlink_and_nonprivate_outputs_refuse(self):
        before = (self.folder / 'manifest.json').read_bytes()
        with self.assertRaisesRegex(kit.KitError, 'OPENING_DESTINATION_EXISTS'):
            opening.enroll(self.folder)
        self.assertEqual((self.folder / 'manifest.json').read_bytes(), before)
        repo = self.case / 'repo'
        subprocess.run(['git', 'init', '-q', str(repo)], check=True, capture_output=True)
        with self.assertRaisesRegex(kit.KitError, 'OUTSIDE_GIT'):
            opening.enroll(repo / 'opening')
        cross_platform = self.case / 'windows-worktree'
        cross_platform.mkdir()
        (cross_platform / '.git').write_text('gitdir: C:/workspace/source/.git/worktrees/linked\n')
        with self.assertRaisesRegex(kit.KitError, 'OUTSIDE_GIT'):
            opening.enroll(cross_platform / 'opening')
        link = self.case / 'link'
        link.symlink_to(self.folder, target_is_directory=True)
        with self.assertRaisesRegex(kit.KitError, 'PATH_CONFLICT'):
            opening.inspect(link, self.expected)
        self.folder.chmod(0o755)
        with self.assertRaisesRegex(kit.KitError, 'OPENING_NOT_PRIVATE'):
            opening.inspect(self.folder, self.expected)

    def test_noninteractive_enrollment_never_reserves_destination(self):
        destination = self.case / 'unattended'
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), 'enroll', '--opening', str(destination)],
                                stdin=subprocess.DEVNULL, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'OPENING_LOCAL_TTY_REQUIRED', result.stderr)
        self.assertFalse(destination.exists())

    def test_native_confirmation_or_unlock_failure_removes_only_new_enrollment(self):
        wrong = secrets.token_urlsafe(24)
        for name, answers in (('mismatch', [self.secret, wrong]),
                              ('wrong-unlock', [self.secret, self.secret, wrong])):
            with self.subTest(name=name):
                destination = self.case / name
                code, output, _ = tty([SCRIPT, 'enroll', '--opening', destination], answers)
                self.assertNotEqual(code, 0)
                self.assertIn(b'OUTER_OPENING=FAIL', output)
                self.assertFalse(destination.exists())
                self.assertFalse(list(self.case.glob('.opening-enroll-*')))
                opening.inspect(self.folder, self.expected)

    def test_cleanup_does_not_remove_a_replaced_reserved_directory(self):
        destination = self.case / 'replacement'
        moved = self.case / 'owned-old'
        def replace(*args, **kwargs):
            destination.rename(moved)
            destination.mkdir(mode=0o700)
            (destination / 'keep').write_bytes(b'concurrent owner bytes')
            raise kit.KitError('INJECTED_BEFORE_KEYGEN')
        with patch.object(opening, 'local_tty'), patch.object(opening, 'native', side_effect=replace):
            with self.assertRaisesRegex(kit.KitError, 'INJECTED_BEFORE_KEYGEN'):
                opening.enroll(destination)
        self.assertEqual((destination / 'keep').read_bytes(), b'concurrent owner bytes')

    def test_changes_during_unlock_cannot_be_reported_verified(self):
        def change(*args):
            path = self.folder / 'identity.age'
            path.write_bytes(path.read_bytes()[:-1])
        with patch.object(opening, 'challenge', side_effect=change):
            with self.assertRaisesRegex(kit.KitError, 'OPENING_HASH_MISMATCH'):
                opening.verify(self.folder, self.expected)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeOpening))
    print(json.dumps({'opening_cases': result.testsRun, 'result': 'PASS' if result.wasSuccessful() else 'FAIL',
                      'real_enrollment_or_devices': 'NOT_PROVEN', 'workstation': 'NOT_PROVEN'}))
    raise SystemExit(0 if result.wasSuccessful() else 1)
