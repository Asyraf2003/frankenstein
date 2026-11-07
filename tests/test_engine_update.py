import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import engine_update as engine


class Backend:
    def __init__(self, desktop=True):
        self.versions = {role: '0.2.0-1' for role in engine.ROLES[:2 if desktop else 1]}
        self.fail = None
        self.corrupt = False
        self.busy = False
        self.transactions = []

    def installed(self):
        return dict(self.versions)

    def package(self, path):
        value = json.loads(path.read_text())
        return value['name'], value['version']

    def available(self):
        engine.require(not self.busy, 'pacman database is locked')

    def verify(self, versions):
        engine.require(self.versions == versions and not self.corrupt, 'native package verification failed')

    def install(self, paths):
        self.transactions.append(paths)
        for path in paths:
            name, version = self.package(path)
            self.versions[name] = version
            if self.fail == 'partial':
                raise engine.Error('synthetic interrupted pacman')
        if self.fail == 'after':
            raise engine.Error('synthetic interruption after package commit')


class EngineUpdates(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='engine-proof-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.backend = Backend()
        self.manager = engine.Generations(self.root / 'engine', self.backend, self.cache)
        for role in engine.ROLES:
            self.package(self.cache, role, '0.2.0-1')

    def package(self, directory, role, version, marker='original'):
        path = directory / (role + '-' + version + '-any.pkg.tar.zst')
        path.write_text(json.dumps({'name': role, 'version': version, 'marker': marker}))
        path.chmod(0o600)
        return path

    def stage(self, tag, destination):
        destination.mkdir()
        packages = {}
        for role in engine.ROLES:
            path = self.package(destination, role, tag[1:] + '-1', 'release')
            packages[path.name] = engine.sha(path)
        (destination / 'engine.json').write_text(json.dumps({'version': tag[1:], 'commit': 'a' * 40, 'packages': packages}))
        return destination

    def test_update_and_rollback_preserve_exact_previous_packages_and_user_state(self):
        user = self.root / 'private-user-state'
        user.write_bytes(b'opaque owner data')
        applied = self.manager.apply('v0.3.0', self.stage)
        self.assertEqual(set(self.backend.installed().values()), {'0.3.0-1'})
        previous = self.manager.rollback()
        self.assertEqual(set(self.backend.installed().values()), {'0.2.0-1'})
        self.assertNotEqual(applied['id'], previous['id'])
        self.assertEqual(user.read_bytes(), b'opaque owner data')
        self.assertTrue((self.manager.root / applied['id']).is_dir())
        self.assertEqual(self.manager.status()['receipt']['history'], [])

    def test_core_only_does_not_install_openbox(self):
        self.backend.versions.pop('frankenstein-openbox')
        self.manager.apply('v0.3.0', self.stage)
        self.assertEqual(self.backend.installed(), {'frankenstein-core': '0.3.0-1'})
        self.manager.rollback()
        self.assertEqual(self.backend.installed(), {'frankenstein-core': '0.2.0-1'})

    def test_same_version_baseline_still_installs_attested_release_once(self):
        self.manager.apply('v0.2.0', self.stage)
        self.assertEqual(len(self.backend.transactions), 1)
        self.assertEqual(self.manager.apply('v0.2.0', self.stage)['result'], 'unchanged')
        self.assertEqual(len(self.backend.transactions), 1)

    def test_missing_cached_rollback_package_refuses_before_mutation(self):
        next(self.cache.glob('frankenstein-core*')).unlink()
        with self.assertRaisesRegex(engine.Error, 'absent from pacman cache'):
            self.manager.apply('v0.3.0', self.stage)
        self.assertEqual(self.backend.transactions, [])

    def test_partial_update_requires_explicit_recovery_and_can_restore_previous(self):
        self.backend.fail = 'partial'
        with self.assertRaises(engine.Error):
            self.manager.apply('v0.3.0', self.stage)
        self.assertIsNotNone(self.manager.status()['receipt']['pending'])
        with self.assertRaisesRegex(engine.Error, 'incomplete update'):
            self.manager.apply('v0.4.0', self.stage)
        self.backend.fail = None
        self.manager.recover('previous')
        self.assertEqual(set(self.backend.installed().values()), {'0.2.0-1'})
        self.assertIsNone(self.manager.status()['receipt']['pending'])

    def test_failure_after_native_commit_can_finish_target_then_rollback(self):
        self.backend.fail = 'after'
        with self.assertRaises(engine.Error):
            self.manager.apply('v0.3.0', self.stage)
        self.backend.fail = None
        self.manager.recover('target')
        self.assertEqual(set(self.backend.installed().values()), {'0.3.0-1'})
        self.manager.rollback()
        self.assertEqual(set(self.backend.installed().values()), {'0.2.0-1'})

    def test_interrupted_rollback_can_retry_target(self):
        self.manager.apply('v0.3.0', self.stage)
        self.backend.fail = 'partial'
        with self.assertRaises(engine.Error):
            self.manager.rollback()
        self.backend.fail = None
        self.manager.recover('target')
        self.assertEqual(set(self.backend.installed().values()), {'0.2.0-1'})
        self.assertEqual(self.manager.status()['receipt']['history'], [])

    def test_external_version_drift_is_not_overwritten(self):
        self.manager.apply('v0.3.0', self.stage)
        self.backend.versions['frankenstein-core'] = '9.9.9-1'
        before = len(self.backend.transactions)
        with self.assertRaises(engine.Error):
            self.manager.rollback()
        with self.assertRaisesRegex(engine.Error, 'drifted'):
            self.manager.apply('v0.4.0', self.stage)
        self.assertEqual(len(self.backend.transactions), before)

    def test_tampered_generation_or_native_files_are_rejected(self):
        applied = self.manager.apply('v0.3.0', self.stage)
        retained = self.manager.root / applied['id'] / applied['packages']['frankenstein-core']['file']
        retained.write_text('corrupted')
        with self.assertRaisesRegex(engine.Error, 'retained package changed'):
            self.manager.rollback()

    def test_package_metadata_mismatch_and_unverified_stage_fail_before_install(self):
        def malicious(tag, destination):
            self.stage(tag, destination)
            path = next(destination.glob('frankenstein-core*'))
            path.write_text('modified after verification')
            return destination
        with self.assertRaisesRegex(engine.Error, 'verified release package changed'):
            self.manager.apply('v0.3.0', malicious)
        self.assertEqual(self.backend.transactions, [])

    def test_locked_pacman_does_not_start_transaction(self):
        self.backend.busy = True
        with self.assertRaisesRegex(engine.Error, 'locked'):
            self.manager.apply('v0.3.0', self.stage)
        self.assertIsNone(self.manager.index())

    def test_private_store_rejects_symlink(self):
        self.manager.root.symlink_to(self.cache, target_is_directory=True)
        with self.assertRaises(engine.Error):
            engine.Generations(self.manager.root, self.backend, self.cache)


if __name__ == '__main__':
    unittest.main()
