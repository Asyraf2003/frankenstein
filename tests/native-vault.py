#!/usr/bin/env python3
"""Disposable native age/tar proof. No live inputs, phone, service or cloud."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('recovery_kit', ROOT / 'vault/recovery_kit.py')
kit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kit)


def native(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, check=False)
    if result.returncode:
        raise AssertionError('native fixture command failed: ' + args[0])
    return result.stdout


class Envelope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='native-recovery-kit-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.base = Path(cls.temp.name)
        cls.identities, cls.recipients = [], []
        for name in ('phone', 'pc', 'wrong'):
            identity = cls.base / (name + '.agekey')
            native(['age-keygen', '--output', str(identity)])
            cls.identities.append(identity)
            cls.recipients.append(native(['age-keygen', '-y', str(identity)]).decode().strip())

    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='case-', dir=self.base)
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.stage = self.root / 'staging'
        self.stage.mkdir(mode=0o700)
        self.store = self.root / 'accepted'
        self.ctx = {'revisions': {'engine': '1' * 40, 'state': '2' * 40},
                    'features': ['vault', 'keyring', 'drive', 'projects'],
                    'required_owners': ['credentials', 'recovery', 'keyring', 'vault', 'projects']}
        self.data = {owner + '/dummy.bin': (owner + ':DUMMY_ONLY\n').encode()
                     for owner in self.ctx['required_owners']}
        self.data['vault/dummy.bin'] = bytes(range(256)) * 1024
        for name, content in self.data.items():
            path = self.stage / name
            path.parent.mkdir(mode=0o700, exist_ok=True)
            path.write_bytes(content)

    def candidate(self):
        path = self.root / ('candidate-' + str(len(list(self.root.glob('candidate-*')))) + '.age')
        kit.create(self.stage, self.ctx, self.recipients[:2], path)
        return path

    def baseline(self):
        candidate = self.candidate()
        receipt = kit.promote(candidate, self.identities[0], self.store, self.ctx)
        self.previous = ((self.store / 'latest.json').read_bytes(),
                         self.store / receipt['archive'], candidate.read_bytes())
        return candidate, receipt

    def preserved(self):
        latest, archive, content = self.previous
        self.assertEqual((self.store / 'latest.json').read_bytes(), latest)
        self.assertEqual(archive.read_bytes(), content)

    def metadata(self):
        return {'schema': 1, 'kit_id': 'a' * 32, 'created_at': '2026-10-23T00:00:00+00:00',
                'context': copy.deepcopy(self.ctx),
                'files': {name: {'owner': name.split('/')[0], 'size': len(data),
                                 'sha256': hashlib.sha256(data).hexdigest()}
                          for name, data in self.data.items()}}

    def seal(self, metadata=None, entries=None, manifest_bytes=None):
        """Independent native producer, including malformed candidate fixtures."""
        fd, name = tempfile.mkstemp(suffix='.tar', dir=self.root)
        os.close(fd)
        archive = Path(name)
        if entries is None:
            entries = [('payload/' + name, content, tarfile.REGTYPE)
                       for name, content in self.data.items()]
        if manifest_bytes is None:
            manifest_bytes = json.dumps(metadata if metadata is not None else self.metadata()).encode()
        with tarfile.open(archive, 'w') as output:
            for name, content, kind in [*entries, ('manifest.json', manifest_bytes, tarfile.REGTYPE)]:
                header = tarfile.TarInfo(name)
                header.type, header.mode = kind, 0o600
                header.size = len(content) if kind == tarfile.REGTYPE else 0
                header.linkname = '../../outside' if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ''
                output.addfile(header, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
        encrypted = archive.with_suffix('.age')
        native(['age', '--recipient', self.recipients[0], '--output', str(encrypted), str(archive)])
        return encrypted

    def test_roundtrip_binary_payload_two_native_identities_and_context(self):
        candidate = self.candidate()
        for identity in self.identities[:2]:
            proof = kit.inspect(candidate, identity, self.ctx)
            self.assertEqual(proof['archive_sha256'], hashlib.sha256(candidate.read_bytes()).hexdigest())
            self.assertEqual(proof['manifest']['files'], self.metadata()['files'])
        archive = self.root / 'independent.tar'
        native(['age', '--decrypt', '-i', str(self.identities[1]), '-o', str(archive), str(candidate)])
        with tarfile.open(archive) as source:
            for name, content in self.data.items():
                self.assertEqual(source.extractfile('payload/' + name).read(), content)
        self.assertEqual(candidate.stat().st_mode & 0o777, 0o600)

    def test_missing_owner_and_unpinned_revision_never_publish_candidate(self):
        shutil.rmtree(self.stage / 'vault')
        candidate = self.root / 'missing.age'
        with self.assertRaisesRegex(kit.KitError, 'REQUIRED_OWNER_MISSING'):
            kit.create(self.stage, self.ctx, self.recipients[:1], candidate)
        self.assertFalse(candidate.exists())
        invalid = copy.deepcopy(self.ctx)
        invalid['revisions']['engine'] = 'main'
        with self.assertRaisesRegex(kit.KitError, 'REVISIONS_INVALID'):
            kit.create(self.stage, invalid, self.recipients[:1], candidate)
        self.assertFalse(candidate.exists())

    def test_symlink_and_arbitrary_home_tree_refused(self):
        link = self.stage / 'recovery/alias'
        link.symlink_to(self.stage / 'credentials/dummy.bin')
        with self.assertRaisesRegex(kit.KitError, 'PATH_CONFLICT'):
            self.candidate()
        link.unlink()
        (self.stage / '.config').mkdir()
        with self.assertRaisesRegex(kit.KitError, 'STAGING_OWNER_INVALID'):
            self.candidate()

    def test_existing_candidate_and_output_inside_staging_preserved(self):
        candidate = self.root / 'already.age'
        candidate.write_bytes(b'DUMMY_PREVIOUS_CANDIDATE')
        with self.assertRaisesRegex(kit.KitError, 'CANDIDATE_EXISTS'):
            kit.create(self.stage, self.ctx, self.recipients[:1], candidate)
        self.assertEqual(candidate.read_bytes(), b'DUMMY_PREVIOUS_CANDIDATE')
        with self.assertRaisesRegex(kit.KitError, 'STAGING_OUTPUT_OVERLAP'):
            kit.create(self.stage, self.ctx, self.recipients[:1], self.stage / 'recovery/new.age')

    def test_concurrent_staging_addition_prevents_publication(self):
        original = tarfile.TarFile.addfile
        def change(output, header, stream=None):
            original(output, header, stream)
            if header.name.startswith('payload/'):
                (self.stage / 'recovery/late').write_bytes(b'DUMMY_LATE')
        with patch.object(tarfile.TarFile, 'addfile', change), self.assertRaisesRegex(kit.KitError, 'STAGING_CHANGED'):
            self.candidate()
        self.assertEqual(list(self.root.glob('candidate-*.age')), [])

    def test_wrong_key_and_damaged_final_age_chunk_preserve_current_before_tar(self):
        candidate, _ = self.baseline()
        with self.assertRaisesRegex(kit.KitError, 'AGE_OPERATION_FAILED'):
            kit.promote(candidate, self.identities[2], self.store, self.ctx)
        self.preserved()
        content = candidate.read_bytes()
        for damaged in (content[:-16], content[:-1] + bytes([content[-1] ^ 1])):
            bad = self.root / 'damaged.age'
            bad.write_bytes(damaged)
            partial = self.root / 'partial.tar'
            result = subprocess.run(['age', '-d', '-i', str(self.identities[0]), '-o', str(partial), str(bad)],
                                    stdin=subprocess.DEVNULL, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertGreater(partial.stat().st_size, 0)
            partial.unlink()
            with patch.object(kit.tarfile, 'open', side_effect=AssertionError('tar before final age exit')):
                with self.assertRaisesRegex(kit.KitError, 'AGE_OPERATION_FAILED'):
                    kit.promote(bad, self.identities[0], self.store, self.ctx)
            self.preserved()

    def test_revision_feature_and_required_owner_context_mismatch_preserve_current(self):
        candidate, _ = self.baseline()
        for field, value in (('revisions', {**self.ctx['revisions'], 'engine': '4' * 40}),
                             ('features', ['vault']), ('required_owners', ['vault'])):
            expected = {**self.ctx, field: value}
            with self.assertRaisesRegex(kit.KitError, 'CONTEXT_MISMATCH'):
                kit.promote(candidate, self.identities[0], self.store, expected)
            self.preserved()

    def test_manifest_hash_size_and_missing_owner_refused(self):
        self.baseline()
        for defect in ('hash', 'size', 'owner', 'duplicate_json', 'schema_bool'):
            value = self.metadata()
            name = 'recovery/dummy.bin'
            raw = None
            if defect == 'hash':
                value['files'][name]['sha256'] = '0' * 64
            elif defect == 'size':
                value['files'][name]['size'] += 1
            elif defect == 'owner':
                del value['files']['vault/dummy.bin']
            elif defect == 'duplicate_json':
                raw = json.dumps(value).replace('"schema": 1', '"schema": 1, "schema": 1').encode()
            else:
                value['schema'] = True
            with self.subTest(defect=defect):
                candidate = self.seal(value, manifest_bytes=raw)
                with self.assertRaises(kit.KitError):
                    kit.promote(candidate, self.identities[0], self.store, self.ctx)
                self.preserved()

    def test_extra_traversal_link_and_duplicate_tar_members_never_extract(self):
        self.baseline()
        for extra in (('unlisted', b'dummy', tarfile.REGTYPE),
                      ('payload/../../outside', b'dummy', tarfile.REGTYPE),
                      ('payload/recovery/alias', b'', tarfile.SYMTYPE),
                      ('payload/recovery/hard', b'', tarfile.LNKTYPE),
                      ('payload/recovery/dummy.bin', b'duplicate', tarfile.REGTYPE)):
            entries = [('payload/' + n, data, tarfile.REGTYPE) for n, data in self.data.items()]
            candidate = self.seal(entries=[*entries, extra])
            with self.subTest(name=extra[0]), self.assertRaises(kit.KitError):
                kit.promote(candidate, self.identities[0], self.store, self.ctx)
            self.preserved()
            self.assertFalse((self.root / 'outside').exists())

    def test_failure_before_pointer_switch_keeps_previous_then_retry_retains_both(self):
        _, first = self.baseline()
        second = self.candidate()
        with patch.object(kit.os, 'replace', side_effect=OSError('DUMMY_INTERRUPTION')):
            with self.assertRaises(OSError):
                kit.promote(second, self.identities[0], self.store, self.ctx)
        self.preserved()
        receipt = kit.promote(second, self.identities[1], self.store, self.ctx)
        self.assertNotEqual(receipt['kit_id'], first['kit_id'])
        self.assertEqual(kit.current(self.store), receipt)
        self.assertTrue((self.store / first['archive']).is_file())
        self.assertEqual(len(list(self.store.glob('kit-*.age'))), 2)
        self.assertEqual(kit.promote(second, self.identities[0], self.store, self.ctx), receipt)
        self.assertEqual((self.store / receipt['archive']).stat().st_mode & 0o777, 0o600)

    def test_candidate_changed_after_validation_cannot_become_current(self):
        self.baseline()
        candidate = self.candidate()
        original = kit.inspect
        def changed(*args):
            proof = original(*args)
            candidate.write_bytes(candidate.read_bytes() + b'DUMMY_RACE')
            return proof
        with patch.object(kit, 'inspect', side_effect=changed), self.assertRaisesRegex(kit.KitError, 'CANDIDATE_CHANGED'):
            kit.promote(candidate, self.identities[0], self.store, self.ctx)
        self.preserved()

    def test_validation_hash_is_bound_to_decrypted_copy_not_changed_source(self):
        candidate = self.candidate()
        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
        original = kit.native
        def changed(args):
            candidate.write_bytes(b'DUMMY_REPLACED_AFTER_COPY')
            original(args)
        with patch.object(kit, 'native', side_effect=changed):
            proof = kit.inspect(candidate, self.identities[0], self.ctx)
        self.assertEqual(proof['archive_sha256'], digest)

    def test_version_collision_writer_lock_and_current_drift_preserve_current(self):
        candidate = self.seal()
        receipt = kit.promote(candidate, self.identities[0], self.store, self.ctx)
        self.previous = ((self.store / 'latest.json').read_bytes(),
                         self.store / receipt['archive'], candidate.read_bytes())
        self.data['credentials/dummy.bin'] = b'DUMMY_CHANGED_SAME_ID'
        collision = self.seal()
        with self.assertRaisesRegex(kit.KitError, 'VERSION_CONFLICT'):
            kit.promote(collision, self.identities[0], self.store, self.ctx)
        with kit.writer(self.store), self.assertRaisesRegex(kit.KitError, 'STORE_BUSY'):
            kit.promote(candidate, self.identities[0], self.store, self.ctx)
        self.preserved()
        archive = self.store / receipt['archive']
        archive.write_bytes(b'DUMMY_EXTERNAL_DRIFT')
        with self.assertRaisesRegex(kit.KitError, 'CURRENT_DRIFT'):
            kit.promote(collision, self.identities[0], self.store, self.ctx)
        self.assertEqual(archive.read_bytes(), b'DUMMY_EXTERNAL_DRIFT')
        self.assertEqual((self.store / 'latest.json').read_bytes(), self.previous[0])

    def test_native_cli_requires_expected_context_and_reports_only_format(self):
        context = self.root / 'context.json'
        context.write_text(json.dumps(self.ctx))
        candidate = self.root / 'cli.age'
        command = ['python3', '-B', str(ROOT / 'vault/recovery_kit.py')]
        created = native([*command, 'create', '--staging', str(self.stage), '--context', str(context),
                          '--recipient', self.recipients[0], '--output', str(candidate)])
        self.assertIn(b'KIT_CANDIDATE=CREATED', created)
        checked = native([*command, 'inspect', '--candidate', str(candidate), '--identity', str(self.identities[0]),
                          '--context', str(context)])
        self.assertIn(b'KIT_FORMAT=VALID', checked)
        accepted = native([*command, 'promote', '--candidate', str(candidate), '--identity', str(self.identities[0]),
                           '--context', str(context), '--store', str(self.store)])
        self.assertIn(b'KIT_FORMAT_PROMOTION=PASS', accepted)
        self.assertNotIn(b'WORKSTATION=GREEN', accepted)


if __name__ == '__main__':
    unittest.main(verbosity=2)
