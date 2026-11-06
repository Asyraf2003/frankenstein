import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'installer/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class Installer(unittest.TestCase):
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

    def test_partition_names(self):
        self.assertEqual(installer.partition('/dev/sda', 1), '/dev/sda1')
        self.assertEqual(installer.partition('/dev/nvme0n1', 2), '/dev/nvme0n1p2')
        self.assertEqual(installer.partition('/dev/mmcblk0', 2), '/dev/mmcblk0p2')

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
