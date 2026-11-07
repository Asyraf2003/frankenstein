import copy
from contextlib import nullcontext
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'installer/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class Installer(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'POSIX umask is exercised on Linux')
    def test_private_caller_umask_does_not_break_system_directory_access(self):
        original = os.umask(0o077)
        try:
            def bootstrap(*args):
                with tempfile.TemporaryDirectory() as temp:
                    system = Path(temp) / 'etc'
                    system.mkdir()
                    if os.name != 'nt':
                        self.assertEqual(system.stat().st_mode & 0o777, 0o755)
                    secret = Path(temp) / 'private'
                    secret.mkdir(mode=0o700)
                    if os.name != 'nt':
                        self.assertEqual(secret.stat().st_mode & 0o777, 0o700)
                raise installer.Error('synthetic interrupted bootstrap')
            with patch.object(installer, 'install_target', side_effect=bootstrap):
                with self.assertRaises(installer.Error):
                    installer.install({}, {}, '', '', {})
            retained = os.umask(0o077)
            self.assertEqual(retained, 0o077)
        finally:
            os.umask(original)

    def setUp(self):
        self.disk = {'name': '/dev/vda', 'type': 'disk', 'size': 32 * 1024**3,
                     'ro': False, 'serial': 'DISPOSABLE', 'maj:min': '254:0',
                     'children': [{'name': '/dev/vda1', 'type': 'part', 'mountpoints': [None]}]}

    def test_rejects_mounted_descendants_and_swap(self):
        for mount in ('/', '/run/archiso/bootmnt', '[SWAP]'):
            with self.subTest(mount=mount):
                self.disk['children'][0]['mountpoints'] = [mount]
                with self.assertRaises(installer.Error):
                    installer.validate_disk(self.disk)

    def test_protects_windows_and_ventoy_even_unmounted(self):
        for field, value in [('fstype', 'ntfs'), ('fstype', 'BitLocker'), ('label', 'Ventoy'), ('label', 'VTOYEFI')]:
            disk = copy.deepcopy(self.disk)
            disk['children'][0][field] = value
            with self.subTest(value=value), self.assertRaises(installer.Error):
                installer.validate_disk(disk)

    def test_refuses_partitions_readonly_small_and_mapped_disks(self):
        for field, value in [('type', 'part'), ('ro', True), ('size', 1024)]:
            disk = dict(self.disk, **{field: value})
            with self.subTest(field=field), self.assertRaises(installer.Error):
                installer.validate_disk(disk)
        self.disk['children'][0]['type'] = 'crypt'
        with self.assertRaises(installer.Error):
            installer.validate_disk(self.disk)

    def test_approval_binds_disk_identity(self):
        expected = installer.approval(self.disk)
        for field, value in [('serial', 'ANOTHER'), ('size', 64 * 1024**3), ('name', '/dev/vdb')]:
            self.assertNotEqual(expected, installer.approval(dict(self.disk, **{field: value})))

    def test_disk_change_aborts_before_writes(self):
        with patch.object(installer, 'selected_disk', return_value=dict(self.disk, serial='ANOTHER')), \
             patch.object(installer, 'run') as run:
            with self.assertRaises(installer.Error):
                installer.install(self.disk, {}, '', '', {})
            run.assert_not_called()

    def test_plan_is_read_only(self):
        with patch.object(installer, 'selected_disk', return_value=self.disk), \
             patch.object(installer, 'install') as execute:
            self.assertEqual(installer.main(['--disk', '/dev/vda']), 0)
            execute.assert_not_called()

    def test_execution_requires_an_explicit_engine_channel_before_providers(self):
        with patch.object(installer, 'selected_disk', return_value=self.disk), patch.object(installer, 'run') as run:
            with self.assertRaises(SystemExit) as rejected:
                installer.main(['--disk', '/dev/vda', '--execute'])
            self.assertEqual(rejected.exception.code, 2)
            run.assert_not_called()

    def test_release_failure_never_falls_back_to_embedded_packages(self):
        failure = type('ReleaseError', (Exception,), {})
        provider = SimpleNamespace(Error=failure, owner_credentials=nullcontext)
        def refuse(*args):
            raise failure('untrusted release')
        provider.stage = refuse
        with tempfile.TemporaryDirectory() as temp, patch.dict(sys.modules, {'releases': provider}), \
                patch.object(installer, 'verify_payload') as embedded, patch.object(installer, 'run') as native:
            with self.assertRaisesRegex(installer.Error, 'no experimental fallback'):
                installer.select_engine('v0.2.0', False, temp)
            embedded.assert_not_called()
            native.assert_not_called()

    def test_stable_selection_uses_verified_native_metadata_and_records_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package_bytes = b'synthetic package'
            packages = {f'frankenstein-{role}-0.2.0-1-any.pkg.tar.zst': hashlib.sha256(package_bytes).hexdigest()
                        for role in ('core', 'openbox')}
            manifest = {'version': '0.2.0', 'commit': 'a' * 40, 'packages': packages}
            def stage(tag, output):
                self.assertEqual(tag, 'v0.2.0')
                output.mkdir()
                (output / 'engine.json').write_text(json.dumps(manifest))
                for name in packages:
                    (output / name).write_bytes(package_bytes)
                return output
            provider = SimpleNamespace(Error=RuntimeError, owner_credentials=nullcontext, stage=stage,
                                       validate_manifest=lambda value, tag: value, REPOSITORY='Asyraf2003/frankenstein')
            def native(*args, **kwargs):
                self.assertEqual(args[:2], ('pacman', '-Qp'))
                role, version, release = args[2].name.removesuffix('-any.pkg.tar.zst').rsplit('-', 2)
                return role + ' ' + version + '-' + release
            with patch.dict(sys.modules, {'releases': provider}), patch.object(installer, 'run', native):
                result = installer.select_engine('v0.2.0', False, root)
            self.assertEqual(result['source']['channel'], 'stable')
            self.assertEqual(result['source']['commit'], 'a' * 40)
            self.assertEqual(result['_directory'], root / 'selected-engine')
            (result['_directory'] / next(iter(packages))).write_bytes(b'changed after selection')
            with patch.object(installer, 'run') as writes:
                with self.assertRaisesRegex(installer.Error, 'integrity'):
                    installer.install_target(self.disk, {}, '', '', result)
                writes.assert_not_called()

    def test_release_asset_name_cannot_hide_another_native_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = {'version': '0.2.0', 'commit': 'a' * 40, 'packages': {}}
            for role in ('core', 'openbox'):
                name = f'frankenstein-{role}-0.2.0-1-any.pkg.tar.zst'
                (root / name).write_bytes(b'fixture')
                manifest['packages'][name] = hashlib.sha256(b'fixture').hexdigest()
            (root / 'engine.json').write_text(json.dumps(manifest))
            provider = SimpleNamespace(Error=RuntimeError, owner_credentials=nullcontext, stage=lambda *args: root,
                                       validate_manifest=lambda value, tag: value)
            with patch.dict(sys.modules, {'releases': provider}), patch.object(installer, 'run', return_value='other-package 9-1'):
                with self.assertRaisesRegex(installer.Error, 'metadata differs'):
                    installer.select_engine('v0.2.0', False, root)

    def test_partition_names(self):
        self.assertEqual(installer.partition('/dev/sda', 1), '/dev/sda1')
        self.assertEqual(installer.partition('/dev/nvme0n1', 2), '/dev/nvme0n1p2')
        self.assertEqual(installer.partition('/dev/mmcblk0', 2), '/dev/mmcblk0p2')

    def test_changed_provisioning_aborts_before_disk_mutation(self):
        def changed():
            raise ValueError('phone generation changed')
        with patch.object(installer, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'generation changed'):
                installer.install(self.disk, {}, '', '', {}, {'recheck': changed})
            run.assert_not_called()

    def test_paired_github_is_available_before_release_selection_or_disk_writes(self):
        events = []
        credential = lambda: b'{"tokens":{"access_token":"gho_synthetic_only"}}'
        def provisioned(*args):
            events.append('pair')
            return {'username': 'fixture'}, '1234', 'fixture-disk-secret', {'github_credentials': credential}
        def selection(tag, experimental, temporary, paired):
            events.append('release')
            self.assertIs(paired, credential)
            raise installer.Error('synthetic provenance failure')
        args = SimpleNamespace(phone='fixture', provisioning_bundle=None, engine_release='v0.2.0', experimental_engine=False)
        with patch.object(installer, 'provision_input', side_effect=provisioned), \
             patch.object(installer, 'select_engine', side_effect=selection), \
             patch.object(installer, 'install') as disk, patch.object(installer, 'run') as native:
            with self.assertRaisesRegex(installer.Error, 'provenance failure'):
                installer.execute(args, self.disk, '/synthetic')
            self.assertEqual(events, ['pair', 'release'])
            disk.assert_not_called()
            native.assert_not_called()

    def test_provisioned_fields_are_validated_without_printing_credentials(self):
        entries = {'desired/arch.json': json.dumps({'username': 'alice', 'hostname': 'workstation'}),
                   'credentials/arch-install.json': json.dumps({'password': 'synthetic-account-only',
                                                               'disk_passphrase': 'synthetic-disk-only'})}
        config, password, disk = installer.supplied_fields(entries, json.loads)
        self.assertEqual(config['username'], 'alice')
        self.assertEqual(password, 'synthetic-account-only')
        for accepted in ('1234', 'user', 'abcd'):
            entries['credentials/arch-install.json'] = json.dumps({'password': accepted, 'disk_passphrase': disk})
            self.assertEqual(installer.supplied_fields(entries, json.loads)[1], accepted)
        for invalid in ('123', 'secret\ninjected-command', None, ['not-a-password']):
            entries['credentials/arch-install.json'] = json.dumps({'password': invalid, 'disk_passphrase': disk})
            with self.assertRaises(installer.Error):
                installer.supplied_fields(entries, json.loads)
        entries['credentials/arch-install.json'] = json.dumps({'password': '1234', 'disk_passphrase': '1234'})
        with self.assertRaises(installer.Error):
            installer.supplied_fields(entries, json.loads)

    def test_profile_is_portable_and_rejects_injection(self):
        original = {'username': 'alice', 'hostname': 'workstation', 'timezone': 'Asia/Jakarta'}
        self.assertEqual(installer.profile(original)['packages'], [])
        for field, value in [('username', 'root'), ('username', '-x'), ('hostname', 'host\ncommand'),
                             ('timezone', '../../etc/shadow'), ('packages', ['--root=/']),
                             ('packages', 'vim'), ('password', 'secret')]:
            with self.subTest(field=field), self.assertRaises(installer.Error):
                installer.profile(dict(original, **{field: value}))

    def test_artifact_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(installer, 'PAYLOAD', Path(temp)):
            root = Path(temp)
            (root / 'packages').mkdir()
            packages = {'frankenstein-core-0.2.0-1-any.pkg.tar.zst': '0' * 64,
                        'frankenstein-openbox-0.2.0-1-any.pkg.tar.zst': '0' * 64}
            for name in packages:
                (root / 'packages' / name).write_bytes(b'corrupted')
            (root / 'packages.json').write_text(json.dumps({'version': '0.2.0', 'packages': packages}))
            with self.assertRaises(installer.Error):
                installer.verify_payload()

    def test_duplicate_roles_and_version_drift_fail_before_opening_packages(self):
        for second in ('frankenstein-core-0.2.0-2-any.pkg.tar.zst',
                       'frankenstein-openbox-0.1.0-1-any.pkg.tar.zst', '../outside.pkg.tar.zst'):
            with self.subTest(second=second), tempfile.TemporaryDirectory() as temp, \
                 patch.object(installer, 'PAYLOAD', Path(temp)):
                manifest = {'version': '0.2.0', 'packages': {
                    'frankenstein-core-0.2.0-1-any.pkg.tar.zst': 'a' * 64, second: 'b' * 64}}
                (Path(temp) / 'packages.json').write_text(json.dumps(manifest))
                # No package directory exists: failure must come from manifest validation.
                with self.assertRaises(installer.Error):
                    installer.verify_payload()

    def test_failure_unmounts_before_closing_and_never_announces_success(self):
        calls = []
        def run(*args, **kwargs):
            calls.append(args[0])
            if args[0] == 'mkfs.ext4':
                self.assertEqual(args, ('mkfs.ext4', '-F', '-L', 'frankenstein',
                                        '/dev/mapper/frankenstein-root'))
            if args[0] == 'pacstrap':
                raise installer.Error('download interrupted')
            return ''
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(installer, 'TARGET', Path(temp) / 'target'), \
             patch.object(installer, 'selected_disk', return_value=self.disk), \
             patch.object(installer, 'run', side_effect=run), \
             patch.object(Path, 'read_text', return_value='GenuineIntel'):
            with self.assertRaisesRegex(installer.Error, 'download interrupted'):
                installer.install(self.disk, {'packages': []}, 'not-a-real-secret', 'test-only', {})
        self.assertEqual(calls[-2:], ['umount', 'cryptsetup'])


if __name__ == '__main__':
    unittest.main()
