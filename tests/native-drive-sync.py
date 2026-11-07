"""Actual rclone bisync against disposable local providers, never owner Drive data."""
import importlib.util
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('drive_sync', ROOT / 'lib/drive_sync.py')
drive = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drive)

with tempfile.TemporaryDirectory(prefix='frankenstein-drive-') as tmp:
    root = Path(tmp)
    a, b = root / 'local', root / 'remote'
    a.mkdir(); b.mkdir()
    for directory in (a, b):
        (directory / drive.MARKER).touch()
    (b / 'old.txt').write_text('existing cloud data')
    config = root / 'rclone.conf'
    config.write_text('')
    options = ['--config', str(config)]

    def sync(initial=False):
        drive.pair(a, str(b), root / 'work', root / 'backup-local', str(root / 'backup-remote'), options, initial)

    sync(True)
    assert (a / 'old.txt').read_text() == 'existing cloud data'
    (a / 'new.txt').write_text('saved locally')
    sync()
    assert (b / 'new.txt').read_text() == 'saved locally'
    (b / 'old.txt').write_text('edited on cloud with new size')
    sync()
    assert (a / 'old.txt').read_text() == 'edited on cloud with new size'
    (a / 'new.txt').unlink()
    sync()
    assert not (b / 'new.txt').exists()
    assert (root / 'backup-remote/new.txt').read_text() == 'saved locally'
    (a / drive.MARKER).unlink()
    try:
        sync()
        raise AssertionError('Missing access marker must stop sync')
    except drive.Error:
        assert (b / 'old.txt').is_file()
print('NATIVE_DRIVE_SYNC=PASS: initial pull, upload, remote edit, recoverable deletion, missing-path protection')
