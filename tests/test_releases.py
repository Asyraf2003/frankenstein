import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('releases', ROOT / 'lib/releases.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class Releases(unittest.TestCase):
    def setUp(self):
        self.manifest = {'version': '0.2.0', 'commit': 'a' * 40, 'packages': {
            'frankenstein-core-0.2.0-1-any.pkg.tar.zst': hashlib.sha256(b'package').hexdigest(),
            'frankenstein-openbox-0.2.0-1-any.pkg.tar.zst': hashlib.sha256(b'package').hexdigest()}}
        self.meta = {'draft': False, 'prerelease': False, 'tag_name': 'v0.2.0',
                     'assets': [{'name': n} for n in ['engine.json', *self.manifest['packages']]]}
        self.calls = []

    def api(self, path):
        if path.startswith('releases/tags/'):
            return self.meta
        if path.startswith('git/ref/'):
            return {'object': {'type': 'commit', 'sha': 'a' * 40}}
        if path.startswith('compare/'):
            return {'status': 'ahead'}
        raise AssertionError(path)

    def gh(self, *args):
        self.calls.append(args)
        if args[:2] == ('release', 'download'):
            name = args[args.index('--pattern') + 1]
            path = Path(args[args.index('--dir') + 1]) / name
            path.write_bytes(json.dumps(self.manifest).encode() if name == 'engine.json' else b'package')
        return ''

    def test_rejects_branch_pr_and_prerelease_before_network(self):
        with patch.object(release, 'api') as api:
            for tag in ('main', 'feat/test', 'v0.2.0-rc1', 'refs/pull/7/head', '../main'):
                with self.subTest(tag=tag), self.assertRaises(release.Error):
                    release.stage(tag, 'unused')
            api.assert_not_called()

    def test_draft_and_prerelease_never_download(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(release, 'api', self.api), patch.object(release, 'gh') as gh:
            for flag in ('draft', 'prerelease'):
                self.meta[flag] = True
                with self.assertRaises(release.Error):
                    release.stage('v0.2.0', Path(temp) / 'ready')
                self.meta[flag] = False
            gh.assert_not_called()

    def test_verified_release_stages_both_packages_atomically(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(release, 'api', self.api), patch.object(release, 'gh', self.gh):
            path = release.stage('v0.2.0', Path(temp) / 'ready')
            self.assertEqual(set(p.name for p in path.iterdir()), {'engine.json', *self.manifest['packages']})
            verifies = [c for c in self.calls if c[:2] == ('attestation', 'verify')]
            self.assertEqual(len(verifies), 4)
            for args in verifies:
                self.assertIn(release.WORKFLOW, args)
                self.assertIn('refs/heads/main', args)
            self.assertIn('--source-digest', verifies[-1])

    def test_bad_digest_leaves_no_ready_directory(self):
        self.manifest['packages'][next(iter(self.manifest['packages']))] = '0' * 64
        with tempfile.TemporaryDirectory() as temp, patch.object(release, 'api', self.api), patch.object(release, 'gh', self.gh):
            target = Path(temp) / 'ready'
            with self.assertRaisesRegex(release.Error, 'digest mismatch'):
                release.stage('v0.2.0', target)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_attestation_failure_leaves_no_ready_directory(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(release, 'api', self.api), \
             patch.object(release, 'gh', self.gh), patch.object(release, 'attest', side_effect=release.Error('untrusted signer')):
            with self.assertRaises(release.Error):
                release.stage('v0.2.0', Path(temp) / 'ready')
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_manifest_rejects_path_traversal_missing_role_and_version_mismatch(self):
        for name in ('../../escape', 'frankenstein-core-0.2.0-2-any.pkg.tar.zst',
                     'frankenstein-openbox-0.1.0-1-any.pkg.tar.zst'):
            candidate = copy.deepcopy(self.manifest)
            candidate['packages'].pop('frankenstein-openbox-0.2.0-1-any.pkg.tar.zst')
            candidate['packages'][name] = 'a' * 64
            with self.subTest(name=name), self.assertRaises(release.Error):
                release.validate_manifest(candidate, 'v0.2.0')

    def test_unmerged_source_is_rejected(self):
        def api(path):
            return {'status': 'diverged'} if path.startswith('compare/') else self.api(path)
        with tempfile.TemporaryDirectory() as temp, patch.object(release, 'api', api), patch.object(release, 'gh', self.gh):
            with self.assertRaisesRegex(release.Error, 'not been integrated'):
                release.stage('v0.2.0', Path(temp) / 'ready')
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_portable_owner_token_requires_private_file_and_valid_expiry(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / '.local/state/frankenstein/ecosystem/state/credentials/github.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({'tokens': {'access_token': 'gho_synthetic_fixture_only'}}))
            path.chmod(0o600)
            self.assertEqual(release.user_token(temporary, os.getuid()), 'gho_synthetic_fixture_only')
            path.chmod(0o644)
            with self.assertRaisesRegex(release.Error, 'private'):
                release.user_token(temporary, os.getuid())
            path.chmod(0o600)
            path.write_text(json.dumps({'tokens': {'access_token': 'gho_synthetic_fixture_only', 'expires_at': 1}}))
            with self.assertRaisesRegex(release.Error, 'expired'):
                release.user_token(temporary, os.getuid())

    def test_owner_session_is_scoped_to_release_operation_and_never_in_arguments(self):
        with patch.dict(os.environ, {'GH_HOST': 'different.example'}, clear=True), \
                patch.object(release, 'user_token', return_value='gho_synthetic_fixture_only'), \
                patch.object(release.subprocess, 'run') as native:
            with self.assertRaisesRegex(RuntimeError, 'synthetic failure'):
                with release.owner_credentials():
                    self.assertEqual(os.environ['GH_HOST'], 'github.com')
                    self.assertEqual(os.environ['GH_TOKEN'], 'gho_synthetic_fixture_only')
                    raise RuntimeError('synthetic failure')
            self.assertNotIn('GH_TOKEN', os.environ)
            self.assertEqual(os.environ['GH_HOST'], 'different.example')
            native.assert_not_called()


if __name__ == '__main__':
    unittest.main()
