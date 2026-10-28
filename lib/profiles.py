#!/usr/bin/env python3
"""Explicit user-file generations, with drift refusal and recoverable rollback."""
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import uuid

ASSETS = Path('/usr/share/frankenstein/profiles')


class Error(Exception):
    pass


def safe(path, directory=False):
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise Error('symlink refused: ' + str(parent))
    if path.exists():
        if path.stat().st_uid != os.getuid():
            raise Error('foreign owner: ' + str(path))
        if directory != path.is_dir() or (not directory and not path.is_file()):
            raise Error('unexpected file type: ' + str(path))


def snapshot(path):
    safe(path)
    if not path.exists():
        return None
    data = path.read_bytes()
    if len(data) > 1024 * 1024:
        raise Error('profile file exceeds 1 MiB: ' + str(path))
    return {'data': base64.b64encode(data).decode(), 'mode': stat.S_IMODE(path.stat().st_mode)}


def atomic(path, data, mode):
    safe(path)
    for parent in path.parents:
        if parent.exists():
            if not parent.is_dir() or parent.is_symlink():
                raise Error('unsafe parent: ' + str(parent))
            break
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.frankenstein-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        parentfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parentfd)
        finally:
            os.close(parentfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def save(path, value):
    atomic(path, (json.dumps(value, sort_keys=True) + '\n').encode(), 0o600)


def restore(path, value):
    if value is None:
        safe(path)
        path.unlink(missing_ok=True)
    else:
        atomic(path, base64.b64decode(value['data'], validate=True), value['mode'])


class Profiles:
    def __init__(self, home=None, assets=None):
        self.home = Path(home) if home else Path.home()
        self.assets = Path(assets) if assets else ASSETS
        if not self.home.is_absolute() or self.home == Path('/'):
            raise Error('HOME must be an absolute user directory')
        safe(self.home, directory=True)
        self.state = self.home / '.local/state/frankenstein/profiles'
        self.current = self.state / 'current.json'
        self.pending = self.state / 'pending.json'

    def read(self, path, default=None):
        safe(path)
        if not path.exists():
            return default
        if path.stat().st_mode & 0o077:
            raise Error('state must be private: ' + str(path))
        return json.loads(path.read_text())

    def target(self, relative):
        path = Path(relative)
        if path.is_absolute() or not path.parts or '..' in path.parts or str(path).startswith('.local/state/frankenstein'):
            raise Error('invalid profile destination')
        result = self.home / path
        safe(result)
        return result

    def generation(self):
        return self.read(self.current, {'id': None, 'parent': None, 'profiles': [], 'files': {}})

    def verify(self, generation):
        for name, value in generation['files'].items():
            if snapshot(self.target(name)) != value:
                raise Error('managed file drift: ' + name)

    def bundle(self, name):
        if not re_name(name):
            raise Error('invalid profile name')
        root = self.assets / name
        if not (root / 'manifest.json').is_file():
            raise Error('profile is not installed: ' + name)
        manifest = json.loads((root / 'manifest.json').read_text())
        for command in manifest['commands']:
            if not shutil.which(command):
                raise Error('profile dependency missing: ' + command)
        files = {}
        for source, target in manifest['files'].items():
            src = root / source
            if not src.is_relative_to(root) or '..' in Path(source).parts or src.is_symlink():
                raise Error('invalid profile source')
            self.target(target)
            data = src.read_bytes()
            mode = 0o755 if src.stat().st_mode & 0o111 else 0o644
            files[target] = {'data': base64.b64encode(data).decode(), 'mode': mode}
        return files

    def transaction(self, before, after, old, new):
        journal = {'before': before, 'after': after, 'old': old, 'new': new}
        save(self.pending, journal)
        try:
            for name, value in after.items():
                restore(self.target(name), value)
            save(self.current, new)
        except BaseException:
            # Keep the journal. Explicit recover never overwrites unrelated drift.
            raise
        self.pending.unlink()

    def apply(self, name, replace=False):
        old = self.generation()
        self.verify(old)
        desired = self.bundle(name)
        if name in old['profiles'] and all(old['files'].get(k) == v for k, v in desired.items()):
            print('PROFILE=UNCHANGED')
            return
        before = {k: snapshot(self.target(k)) for k in desired}
        for key, value in before.items():
            if key not in old['files'] and value is not None and not replace:
                raise Error('existing file needs explicit --replace: ' + key)
        identifier = uuid.uuid4().hex
        new = {'id': identifier, 'parent': old['id'],
               'profiles': sorted(set(old['profiles']) | {name}),
               'files': {**old['files'], **desired}}
        save(self.state / (identifier + '.json'), {'before': before, 'after': desired, 'old': old, 'new': new})
        self.transaction(before, desired, old, new)
        print('PROFILE=APPLIED GENERATION=' + identifier)

    def rollback(self):
        current = self.generation()
        if not current['id']:
            raise Error('no generation to roll back')
        self.verify(current)
        if not re_name(current['id']):
            raise Error('invalid generation id')
        record = self.read(self.state / (current['id'] + '.json'))
        if not record or record['new'] != current:
            raise Error('generation receipt mismatch')
        self.transaction(record['after'], record['before'], current, record['old'])
        print('PROFILE=ROLLED_BACK')

    def recover(self):
        journal = self.read(self.pending)
        if not journal:
            print('PROFILE=NO_PENDING_TRANSACTION')
            return
        # Preflight the entire set before restoring any file.
        for name, value in journal['before'].items():
            actual = snapshot(self.target(name))
            if actual not in (value, journal['after'][name]):
                raise Error('interrupted transaction has user drift: ' + name)
        if self.generation() not in (journal['old'], journal['new']):
            raise Error('current generation changed during interruption')
        for name, value in journal['before'].items():
            restore(self.target(name), value)
        save(self.current, journal['old'])
        self.pending.unlink()
        print('PROFILE=RECOVERED')

    def run(self, args):
        if args.action == 'list':
            print('\n'.join(sorted(p.parent.name for p in self.assets.glob('*/manifest.json'))))
            return 0
        if args.action in ('status', 'verify'):
            if self.pending.exists():
                raise Error('interrupted transaction; use profile recover')
            current = self.generation()
            self.verify(current)
            print('PROFILE=VERIFIED PROFILES=' + ','.join(current['profiles']))
            return 0
        safe(self.state, directory=True)
        self.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.state.stat().st_mode & 0o077:
            raise Error('profile state directory must be private')
        lockpath = self.state / 'lock'
        safe(lockpath)
        with lockpath.open('a') as lock:
            os.chmod(lockpath, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.action != 'recover' and self.pending.exists():
                raise Error('interrupted transaction; use profile recover')
            if args.action == 'apply':
                self.apply(args.name, args.replace)
            elif args.action == 'rollback':
                self.rollback()
            else:
                self.recover()
        return 0


def re_name(value):
    import re
    return bool(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value))


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='action', required=True)
    for name in ('list', 'status', 'verify', 'rollback', 'recover'):
        subs.add_parser(name)
    apply = subs.add_parser('apply')
    apply.add_argument('name')
    apply.add_argument('--replace', action='store_true')
    args = parser.parse_args(argv)
    try:
        if os.geteuid() == 0:
            raise Error('profiles must run as the target user, without sudo')
        if os.environ.get('XDG_CONFIG_HOME', str(Path.home()/'.config')) != str(Path.home()/'.config'):
            raise Error('this profile requires the default HOME/.config location')
        return Profiles().run(args)
    except (Error, OSError, ValueError, KeyError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        return 2
