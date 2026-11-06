import copy
import hashlib
import importlib.util
import json
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


if __name__ == '__main__':
    unittest.main()
