"""Native encrypted PC/phone reconciliation with a deterministic transport peer."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import device_sync as sync
from device_sync import kit, portable


class Phone:
    def __init__(self, root):
        self.root = root
        root.mkdir()
        self.selected = sync.EMPTY
        self.before_activate = None
        self.after_pull = None
        self.interrupt = False

    def current(self):
        return self.selected

    def pull(self, selected, output):
        shutil.copyfile(self.root / selected, output)
        if self.after_pull:
            self.after_pull()

    def push(self, source):
        if self.interrupt:
            raise EOFError('synthetic disconnect')
        selected = kit.sha(source)
        shutil.copyfile(source, self.root / selected)
        return selected

    def activate(self, selected, previous):
        if self.before_activate:
            self.before_activate()
        kit.require(self.selected == previous, 'SYNC_PHONE_CHANGED')
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            portable.restore(self.root / selected, Path(temporary) / 'proof', selected)
        self.selected = selected


class Reconciliation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='sync-proof-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.pc = self.root / 'ecosystem'
        self.phone = Phone(self.root / 'phone-store')
        self.source = self.root / 'initial.fpe'
        key = self.root / 'identity'
        subprocess.run(['age-keygen', '-o', str(key)], check=True, capture_output=True)
        key.chmod(0o600)
        state = self.root / 'state'
        (state / 'desired').mkdir(parents=True)
        (state / 'desired/profile.json').write_text('{"hostname":"fixture"}')
        context = {'revisions': {'engine': '1' * 40, 'state': '2' * 40},
                   'features': ['fixture'], 'required_owners': ['desired']}
        portable.create(state, key, context, None, None, self.source)

    def populate_pc(self):
        portable.restore(self.source, self.pc, kit.sha(self.source))

    def populate_phone(self):
        self.phone.selected = self.phone.push(self.source)

    def edit_pc(self):
        (self.pc / 'state/desired/profile.json').write_text('{"hostname":"edited"}')

    def test_both_empty_offers_phone_setup(self):
        self.assertEqual(sync.reconcile(self.pc, self.phone)['action'], 'setup-phone')
        self.assertFalse(self.pc.exists())

    def test_discovery_ignores_network_unauthorized_and_offline_devices(self):
        output = 'List of devices attached\nphone device usb:1 product:test\nnetwork:5555 device product:test\nlocked unauthorized usb:2\nlost offline usb:3\n'
        with patch.object(sync.subprocess, 'check_output', return_value=output):
            self.assertEqual(sync.connected('adb'), ['phone'])

    def test_pc_seeds_phone_then_equal_is_noop_despite_random_ciphertext(self):
        self.populate_pc()
        first = sync.reconcile(self.pc, self.phone)
        self.assertEqual(first['action'], 'send-phone')
        selected = self.phone.current()
        self.assertNotEqual(selected, kit.sha(self.source))
        self.assertEqual(sync.reconcile(self.pc, self.phone)['action'], 'unchanged')
        self.assertEqual(selected, self.phone.current())

    def test_phone_seeds_empty_pc(self):
        self.populate_phone()
        self.assertEqual(sync.reconcile(self.pc, self.phone)['action'], 'receive-pc')
        self.assertEqual(sync.reconcile(self.pc, self.phone)['action'], 'unchanged')
        self.assertEqual(self.pc.stat().st_mode & 0o077, 0)

    def test_conflict_requires_choice_and_reports_names_and_dates(self):
        self.populate_pc()
        self.populate_phone()
        self.edit_pc()
        old = self.phone.current()
        result = sync.reconcile(self.pc, self.phone)
        self.assertEqual(result['action'], 'conflict')
        self.assertEqual(result['differences'], ['desired/profile.json'])
        self.assertTrue(result['pc_updated_at'])
        self.assertTrue(result['phone_updated_at'])
        self.assertEqual(self.phone.current(), old)
        self.assertIn('edited', (self.pc / 'state/desired/profile.json').read_text())

    def test_use_phone_retains_old_pc_and_writes_dated_log(self):
        self.populate_pc()
        self.populate_phone()
        self.edit_pc()
        result = sync.reconcile(self.pc, self.phone, decide=lambda p: 'phone')
        self.assertEqual(result['action'], 'receive-pc')
        self.assertIn('edited', (Path(result['retained_pc']) / 'state/desired/profile.json').read_text())
        self.assertIn('fixture', (self.pc / 'state/desired/profile.json').read_text())
        log = (self.root / '.ecosystem-sync/updates.jsonl').read_text()
        self.assertIn('"at":', log)
        self.assertIn('"phase":"complete"', log)
        self.assertNotIn('AGE-SECRET-KEY-', log)

    def test_use_pc_preserves_phone_generation_and_identity(self):
        self.populate_pc()
        self.populate_phone()
        original = self.phone.current()
        self.edit_pc()
        preview = sync.reconcile(self.pc, self.phone, preview=True)
        result = sync.reconcile(self.pc, self.phone, decide=lambda p: 'pc', expected_plan=preview['decision'])
        self.assertEqual(result['action'], 'send-phone')
        self.assertTrue((self.phone.root / original).exists())
        self.assertEqual(sync.reconcile(self.pc, self.phone)['action'], 'unchanged')

    def test_stale_explicit_decision_cannot_replace_either_side(self):
        self.populate_pc()
        self.populate_phone()
        self.edit_pc()
        preview = sync.reconcile(self.pc, self.phone, preview=True)
        (self.pc / 'state/desired/profile.json').write_text('changed after preview')
        before = self.phone.current()
        with self.assertRaisesRegex(kit.KitError, 'SYNC_DECISION_STALE'):
            sync.reconcile(self.pc, self.phone, decide=lambda p: 'pc', expected_plan=preview['decision'])
        self.assertEqual(before, self.phone.current())

    def test_change_while_owner_decides_is_rejected(self):
        self.populate_pc()
        self.populate_phone()
        self.edit_pc()
        def choice(plan):
            (self.pc / 'state/desired/profile.json').write_text('during decision')
            return 'phone'
        with self.assertRaisesRegex(kit.KitError, 'SYNC_PC_CHANGED'):
            sync.reconcile(self.pc, self.phone, decide=choice)
        self.assertIn('during decision', (self.pc / 'state/desired/profile.json').read_text())

    def test_changed_phone_during_pull_is_rejected(self):
        self.populate_phone()
        self.phone.after_pull = lambda: setattr(self.phone, 'selected', 'f' * 64)
        with self.assertRaisesRegex(kit.KitError, 'SYNC_PHONE_CHANGED'):
            sync.reconcile(self.pc, self.phone)
        self.assertFalse(self.pc.exists())

    def test_disconnected_upload_never_activates(self):
        self.populate_pc()
        self.phone.interrupt = True
        with self.assertRaises(EOFError):
            sync.reconcile(self.pc, self.phone)
        self.assertEqual(self.phone.current(), sync.EMPTY)
        self.assertTrue(self.pc.exists())

    def test_activation_race_cannot_overwrite_new_selection(self):
        self.populate_pc()
        self.phone.before_activate = lambda: setattr(self.phone, 'selected', 'f' * 64)
        with self.assertRaisesRegex(kit.KitError, 'SYNC_PHONE_CHANGED'):
            sync.reconcile(self.pc, self.phone)
        self.assertEqual(self.phone.current(), 'f' * 64)

    def test_incomplete_existing_pc_is_not_treated_as_empty(self):
        self.populate_phone()
        self.pc.mkdir()
        with self.assertRaises(OSError):
            sync.reconcile(self.pc, self.phone)
        self.assertEqual(list(self.pc.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
