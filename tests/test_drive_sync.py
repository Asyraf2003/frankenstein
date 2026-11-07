import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('drive_sync', ROOT / 'lib/drive_sync.py')
drive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drive)


class DriveSync(unittest.TestCase):
    def test_prepare_creates_only_three_folders_without_login_or_remote_operations(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(drive, 'run') as native:
            root = Path(tmp)
            result = drive.main(['prepare', '--local', str(root / 'home'), '--ecosystem', str(root / 'phone'), '--state', str(root / 'private')])
            self.assertEqual(result, 0)
            self.assertEqual({p.name for p in (root / 'home').iterdir()}, {'downloads', 'media', 'documents'})
            native.assert_not_called()

    def test_conflicting_initial_data_stops_before_mutation(self):
        left = [{'Path': 'old.txt', 'Size': 3, 'Hashes': {'md5': 'a'}}]
        right = [{'Path': 'old.txt', 'Size': 3, 'Hashes': {'md5': 'b'}}]
        with patch.object(drive, 'run', side_effect=[json.dumps(left), json.dumps(right)]) as native:
            with self.assertRaisesRegex(drive.Error, 'differ'):
                drive.pair('/local', 'google:downloads', Path('/work'), '/backup', 'google:history', [], True)
            self.assertEqual([c.args[0] for c in native.call_args_list], ['lsjson', 'lsjson'])

    def test_regular_sync_never_implicitly_resets_baseline(self):
        with patch.object(drive, 'run') as native:
            drive.pair('/local', 'google:downloads', Path('/work'), '/backup', 'google:history', [])
            args = native.call_args.args
            self.assertNotIn('--resync', args)
            self.assertIn('--check-access', args)
            self.assertIn('--backup-dir1', args)
            self.assertIn('--backup-dir2', args)
            self.assertEqual(args[args.index('--conflict-resolve') + 1], 'none')

    def test_phone_account_mismatch_never_imports_credentials(self):
        # This checks account identity, independently of the shared Git-boundary
        # guard (minimal package-build environments need not have git installed).
        with tempfile.TemporaryDirectory() as tmp, patch.object(drive.kit, 'outside_git', side_effect=lambda p: Path(p).absolute()):
            root = Path(tmp)
            (root / 'state/desired').mkdir(parents=True)
            (root / 'state/credentials').mkdir()
            (root / 'state/desired/user.json').write_text('{"google_email":"owner@example.com"}')
            (root / 'state/credentials/google-drive.json').write_text('{"account":"other@example.com"}')
            with self.assertRaisesRegex(drive.Error, 'does not match'):
                drive.phone_credentials(root)

    def test_missing_marker_or_provider_failure_does_not_resync(self):
        with patch.object(drive, 'run', side_effect=drive.Error('inaccessible')) as native:
            with self.assertRaises(drive.Error):
                drive.pair('/local', 'google:downloads', Path('/work'), '/backup', 'google:history', [])
            self.assertEqual(native.call_count, 1)
            self.assertNotIn('--resync', native.call_args.args)

    def test_reauthorization_updates_token_without_resetting_existing_sync(self):
        credential = {'account': 'owner@example.com', 'client_id': 'fixture.apps.googleusercontent.com',
                      'access_token': 'synthetic-access', 'refresh_token': 'synthetic-refresh'}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(drive.kit, 'outside_git', side_effect=lambda p: Path(p).absolute()), \
             patch.object(drive, 'phone_credentials', return_value=credential), \
             patch.object(drive, 'mypc') as folder, patch.object(drive, 'run') as native:
            root = Path(tmp)
            state, home = root / 'private', root / 'home'
            state.mkdir(); home.mkdir()
            selected = state / 'selection.json'
            selected.write_text(json.dumps({'schema': 1, 'account': credential['account'], 'folder_id': 'existing', 'local': str(home)}))
            for name in drive.FOLDERS:
                (home / name).mkdir()
                (state / (name + '.ready')).write_text('verified\n')
            args = ['setup', '--state', str(state), '--local', str(home)]
            self.assertEqual(drive.main(args), 0)
            config = state / 'rclone.conf'
            self.assertIn('synthetic-refresh', config.read_text())
            config.write_text('provider-refreshed-session')
            self.assertEqual(drive.main(args), 0)
            self.assertEqual(config.read_text(), 'provider-refreshed-session')
            credential['refresh_token'] = 'new-phone-authorization'
            self.assertEqual(drive.main(args), 0)
            self.assertIn('new-phone-authorization', config.read_text())
            self.assertEqual(json.loads(selected.read_text())['folder_id'], 'existing')
            folder.assert_not_called()
            self.assertEqual(native.call_count, 9)
            for call in native.call_args_list:
                self.assertEqual(call.args[0], 'bisync')
                self.assertNotIn('--resync', call.args)


if __name__ == '__main__':
    unittest.main()
