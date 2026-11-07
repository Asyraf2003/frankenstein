"""Retained native engine package generations; never a whole-OS rollback claim."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import uuid

import releases

ROLES = ('frankenstein-core', 'frankenstein-openbox')
STORE = Path('/var/lib/frankenstein/engine')
CACHE = Path('/var/cache/pacman/pkg')


class Error(ValueError):
    pass


def require(value, message):
    if not value:
        raise Error(message)


def safe(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink in engine storage')
    return path


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write(path, value):
    safe(path)
    fd, temporary = tempfile.mkstemp(prefix='.receipt-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        sync(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


class Pacman:
    def command(self, *arguments, missing=False):
        result = subprocess.run(['/usr/bin/pacman', *map(str, arguments)], text=True, capture_output=True)
        if missing and result.returncode == 1:
            return None
        require(result.returncode == 0, 'pacman operation failed; inspect native pacman logs')
        return result.stdout.strip()

    def available(self):
        require(not Path('/var/lib/pacman/db.lck').exists(), 'pacman database is locked; do not remove a live lock')

    def installed(self):
        result = {}
        for role in ROLES:
            line = self.command('-Q', role, missing=True)
            if line:
                name, version = line.split()
                require(name == role, 'unexpected installed package')
                result[name] = version
        return result

    def package(self, path):
        name, version = self.command('-Qp', path).split()
        require(name in ROLES, 'not a Frankenstein engine package')
        return name, version

    def install(self, paths):
        self.available()
        # Native dependency checks and package hooks remain enabled.
        self.command('-U', '--noconfirm', '--', *paths)

    def verify(self, versions):
        require(self.installed() == versions, 'installed engine versions do not match the selected generation')
        self.command('-Qkk', *sorted(versions))


class Generations:
    def __init__(self, root=STORE, backend=None, cache=CACHE):
        self.root, self.cache = safe(root), safe(cache)
        self.backend = backend or Pacman()

    @contextmanager
    def locked(self):
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.stat()
        require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, 'engine storage must be private and owned by this administrator')
        with safe(self.root / 'writer.lock').open('a+b') as lock:
            os.fchmod(lock.fileno(), 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error('another engine operation is running') from None
            yield

    def index(self):
        path = safe(self.root / 'current.json')
        if not path.exists():
            return None
        value = json.loads(path.read_text())
        require(set(value) == {'schema', 'current', 'history', 'pending'} and value['schema'] == 1,
                'invalid engine transaction receipt')
        require(isinstance(value['history'], list) and len(value['history']) <= 10000, 'invalid generation history')
        self.generation(value['current'])
        for identifier in value['history']:
            self.identifier(identifier)
        if value['pending'] is not None:
            pending = value['pending']
            require(set(pending) == {'from', 'to', 'kind'} and pending['from'] == value['current']
                    and pending['kind'] in ('update', 'rollback'), 'invalid pending transaction')
            self.generation(pending['to'])
        return value

    def identifier(self, identifier):
        require(isinstance(identifier, str) and re.fullmatch('[0-9a-f]{32}', identifier), 'invalid generation identifier')
        return identifier

    def generation(self, identifier):
        folder = safe(self.root / self.identifier(identifier))
        value = json.loads((folder / 'generation.json').read_text())
        require(set(value) == {'id', 'created_at', 'source', 'packages'} and value['id'] == identifier,
                'invalid package generation')
        require(isinstance(value['packages'], dict) and 'frankenstein-core' in value['packages']
                and set(value['packages']) <= set(ROLES), 'invalid generation package roles')
        for role, package in value['packages'].items():
            require(set(package) == {'file', 'version', 'sha256'} and
                    re.fullmatch(re.escape(role) + r'-[A-Za-z0-9_.:+-]+\.pkg\.tar\.zst', package['file'])
                    and re.fullmatch('[0-9a-f]{64}', package['sha256']), 'invalid retained package record')
            path = safe(folder / package['file'])
            require(path.is_file() and sha(path) == package['sha256'], 'retained package changed')
            require(self.backend.package(path) == (role, package['version']), 'retained package metadata changed')
        return value

    @staticmethod
    def versions(generation):
        return {name: package['version'] for name, package in generation['packages'].items()}

    def archive(self, paths, versions, source):
        identifier = uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix='.generation-', dir=self.root) as temporary:
            folder = Path(temporary)
            packages = {}
            for original in paths:
                original = safe(original)
                require(original.is_file(), 'package file missing')
                name, version = self.backend.package(original)
                require(name not in packages and versions.get(name) == version, 'package version/role mismatch')
                expected_name = name + '-' + version + '-any.pkg.tar.zst'
                require(original.name == expected_name, 'package filename does not match native metadata')
                copied = folder / expected_name
                shutil.copyfile(original, copied)
                copied.chmod(0o600)
                require(sha(copied) == sha(original), 'package changed while archiving')
                with copied.open('rb') as stream:
                    os.fsync(stream.fileno())
                packages[name] = {'file': copied.name, 'version': version, 'sha256': sha(copied)}
            require(set(packages) == set(versions), 'missing engine package for rollback')
            value = {'id': identifier, 'created_at': datetime.now(timezone.utc).isoformat(),
                     'source': source, 'packages': packages}
            write(folder / 'generation.json', value)
            folder.rename(self.root / identifier)
            sync(self.root)
        return self.generation(identifier)

    def baseline(self, versions):
        require('frankenstein-core' in versions, 'install Frankenstein core before updating')
        paths = []
        for name, version in versions.items():
            path = safe(self.cache / (name + '-' + version + '-any.pkg.tar.zst'))
            require(path.is_file(), 'original installed package is absent from pacman cache; preserve it before updating')
            require(path.stat().st_uid == os.geteuid() and path.stat().st_mode & 0o022 == 0,
                    'original package cache is not administrator-owned')
            paths.append(path)
        value = self.archive(paths, versions, {'kind': 'installed-baseline'})
        receipt = {'schema': 1, 'current': value['id'], 'history': [], 'pending': None}
        write(self.root / 'current.json', receipt)
        return receipt

    def finish(self, receipt):
        pending = receipt['pending']
        if pending['kind'] == 'update':
            receipt['history'].append(pending['from'])
        else:
            require(receipt['history'] and receipt['history'][-1] == pending['to'], 'rollback history changed')
            receipt['history'].pop()
        receipt['current'] = pending['to']
        receipt['pending'] = None
        write(self.root / 'current.json', receipt)

    def transition(self, receipt, target, kind):
        self.backend.available()
        self.backend.verify(self.versions(self.generation(receipt['current'])))
        receipt['pending'] = {'from': receipt['current'], 'to': target['id'], 'kind': kind}
        write(self.root / 'current.json', receipt)  # Durable before native mutation.
        self.backend.install([self.root / target['id'] / p['file'] for p in target['packages'].values()])
        self.backend.verify(self.versions(target))
        self.finish(receipt)
        return target

    def apply(self, tag, stage=releases.stage):
        with self.locked():
            self.backend.available()
            receipt = self.index()
            require(receipt is None or receipt['pending'] is None, 'incomplete update; inspect status and recover first')
            installed = self.backend.installed()
            require('frankenstein-core' in installed, 'install Frankenstein core before updating')
            self.backend.verify(installed)
            if receipt:
                require(installed == self.versions(self.generation(receipt['current'])), 'installed package versions drifted')
            with tempfile.TemporaryDirectory(prefix='.release-', dir=self.root) as temporary:
                staged = stage(tag, Path(temporary) / 'verified')
                manifest = releases.validate_manifest(json.loads((staged / 'engine.json').read_text()), tag)
                paths, versions = [], {}
                for name, expected in manifest['packages'].items():
                    path = safe(staged / name)
                    require(sha(path) == expected, 'verified release package changed')
                    role, version = self.backend.package(path)
                    if role in installed:
                        require(version.startswith(manifest['version'] + '-'), 'release package version mismatch')
                        paths.append(path)
                        versions[role] = version
                require(set(versions) == set(installed), 'release does not cover installed engine roles')
                if receipt and versions == installed:
                    current = self.generation(receipt['current'])
                    if current['source'].get('commit') == manifest['commit'] and all(
                            p['sha256'] == manifest['packages'].get(p['file']) for p in current['packages'].values()):
                        return {'result': 'unchanged', 'versions': versions}
                receipt = receipt or self.baseline(installed)
                target = self.archive(paths, versions, {'kind': 'stable-release', 'version': manifest['version'], 'commit': manifest['commit']})
                return self.transition(receipt, target, 'update')

    def rollback(self):
        with self.locked():
            receipt = self.index()
            require(receipt and receipt['pending'] is None, 'no complete engine state; inspect status and recover')
            require(receipt['history'], 'no earlier engine generation')
            return self.transition(receipt, self.generation(receipt['history'][-1]), 'rollback')

    def recover(self, use):
        require(use in ('previous', 'target'), 'choose previous or target')
        with self.locked():
            receipt = self.index()
            require(receipt and receipt['pending'], 'no interrupted engine transaction')
            pending = receipt['pending']
            old, target = self.generation(pending['from']), self.generation(pending['to'])
            before, after = self.versions(old), self.versions(target)
            actual = self.backend.installed()
            require(all(name in before and version in (before[name], after[name]) for name, version in actual.items()),
                    'engine versions changed outside the interrupted transaction')
            selected = old if use == 'previous' else target
            self.backend.available()
            self.backend.install([self.root / selected['id'] / p['file'] for p in selected['packages'].values()])
            self.backend.verify(self.versions(selected))
            if use == 'target':
                self.finish(receipt)
            else:
                receipt['pending'] = None
                write(self.root / 'current.json', receipt)
            return selected

    def status(self):
        with self.locked():
            receipt = self.index()
            return {'installed': self.backend.installed(), 'receipt': receipt,
                    'scope': 'Frankenstein engine packages only; user state and OS packages are separate'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('apply').add_argument('tag')
    commands.add_parser('status')
    commands.add_parser('rollback')
    commands.add_parser('recover').add_argument('--use', required=True, choices=('previous', 'target'))
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, 'engine package updates require administrator access')
        manager = Generations()
        if args.action == 'apply':
            with releases.owner_credentials():
                result = manager.apply(args.tag)
        elif args.action == 'recover':
            result = manager.recover(args.use)
        else:
            result = getattr(manager, args.action)()
        print(json.dumps(result, indent=2))
        return 0
    except (Error, releases.Error, OSError, ValueError, KeyError, TypeError) as error:
        print('ENGINE=FAIL (' + str(error) + ')')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
