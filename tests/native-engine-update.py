"""Exercise real pacman update/rollback only in the disposable Arch test container."""
import json
from contextlib import nullcontext
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
from unittest.mock import patch

assert Path('/.dockerenv').is_file() and os.environ.get('FRANKENSTEIN_DISPOSABLE') == '1'
sys.path.insert(0, '/usr/lib/frankenstein')
import engine_update as engine

manager = engine.Generations()
original = manager.backend.installed()
assert original and set(original.values()) == {'0.2.0-1'}
marker = Path('/usr/lib/frankenstein/control.py')
before = marker.read_bytes()
private = Path('/home/tester/engine-private-fixture')
private.write_bytes(b'private owner bytes retained')
private.chmod(0o600)


def fixture_stage(tag, destination):
    assert tag == 'v0.2.1'
    destination.mkdir()
    packages = {}
    for source in Path('/engine-fixture/packaging').glob('*.pkg.tar.zst'):
        target = destination / source.name
        shutil.copyfile(source, target)
        packages[target.name] = engine.sha(target)
    (destination / 'engine.json').write_text(json.dumps({'version': '0.2.1', 'commit': 'a' * 40, 'packages': packages}))
    return destination


# The installer and updater select identical native package bytes. This fixture
# replaces network/provenance staging only; it does not claim a public release.
spec = importlib.util.spec_from_file_location('installer', Path(__file__).resolve().parents[1] / 'installer/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
with tempfile.TemporaryDirectory(prefix='native-stable-selection-') as temporary, \
        patch.object(engine.releases, 'stage', fixture_stage), patch.object(engine.releases, 'owner_credentials', nullcontext):
    selected = installer.select_engine('v0.2.1', False, temporary)
    assert selected['source']['channel'] == 'stable'
    assert selected['source']['commit'] == 'a' * 40
    for name in selected['packages']:
        assert engine.sha(selected['_directory'] / name) == engine.sha(Path('/engine-fixture/packaging') / name)
print('NATIVE_INSTALLER_RELEASE_SELECTION=PASS package-metadata-and-bytes; remote-provenance-fixtured')

target = manager.apply('v0.2.1', fixture_stage)
assert set(manager.backend.installed()) == set(original)
assert set(manager.backend.installed().values()) == {'0.2.1-1'}
assert b'ENGINE_FIXTURE_MARKER' in marker.read_bytes()
assert manager.apply('v0.2.1', fixture_stage)['result'] == 'unchanged'
manager.rollback()
assert manager.backend.installed() == original
assert marker.read_bytes() == before
assert private.read_bytes() == b'private owner bytes retained'
assert manager.status()['receipt']['pending'] is None
assert (manager.root / target['id']).is_dir()
# Lose the updater reply after a real native package commit. A fresh controller
# must observe the durable journal and honor either explicit recovery choice.
class LostReply(engine.Pacman):
    def install(self, paths):
        super().install(paths)
        raise engine.Error('fixture lost reply after real pacman commit')

for choice in ('previous', 'target'):
    broken = engine.Generations(backend=LostReply())
    try:
        broken.apply('v0.2.1', fixture_stage)
    except engine.Error as error:
        assert 'fixture lost reply' in str(error)
    else:
        raise AssertionError('expected interrupted update')
    fresh = engine.Generations()
    assert fresh.status()['receipt']['pending'] is not None
    fresh.recover(choice)
    assert fresh.status()['receipt']['pending'] is None
    if choice == 'target':
        assert b'ENGINE_FIXTURE_MARKER' in marker.read_bytes()
        fresh.rollback()
    assert marker.read_bytes() == before
    assert private.read_bytes() == b'private owner bytes retained'
print('NATIVE_ENGINE_INTERRUPTED_RECOVERY=PASS previous,target')
print('NATIVE_ENGINE_UPDATE_ROLLBACK=PASS roles=' + ','.join(sorted(original)))
