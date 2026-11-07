"""Run an enrolled Vaultwarden service and preserve native encrypted backups."""
import argparse
import base64
from contextlib import closing, contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time
import uuid
from urllib.parse import quote

HELD_LOCKS = ContextVar('vault_service_locks', default=())


class Error(ValueError):
    pass


def require(value, message):
    if not value:
        raise Error(message)


def safe(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink in service storage')
    require(not any((p / '.git').exists() for p in (path, *path.parents)), 'private service storage must be outside Git')
    return path


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private(path):
    path = safe(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(path.stat().st_uid == os.geteuid() and stat.S_IMODE(path.stat().st_mode) == 0o700,
            'private administrator-owned directory required')
    return path


def save(path, value):
    path = safe(path)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.write-')
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(value, output, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
        sync(path.parent)
    finally:
        Path(name).unlink(missing_ok=True)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(command, timeout=120):
    result = subprocess.run(list(map(str, command)), capture_output=True, timeout=timeout, pass_fds=HELD_LOCKS.get())
    require(result.returncode == 0, 'native provider failed: ' + Path(str(command[0])).name + '; output withheld')
    return result.stdout


def database(data):
    db = safe(data / 'db.sqlite3')
    require(db.is_file(), 'existing Vaultwarden database required; refusing to initialize an empty vault')
    with closing(sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)) as connection:
        require(connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'database integrity check failed')
        tables = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        require({'users', 'ciphers'} <= tables, 'not a Vaultwarden database')
        return {name: connection.execute('SELECT count(*) FROM ' + name).fetchone()[0] for name in ('users', 'ciphers')}


def inventory(data):
    result = {}
    for path in sorted(data.rglob('*')):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'vault links and special files refused')
        if path.is_file():
            if path.parent == data and (path.name == 'db.sqlite3-shm' or (path.name == 'db.sqlite3-wal' and info.st_size == 0)):
                continue
            result[str(path.relative_to(data))] = [info.st_size, info.st_mtime_ns, info.st_ctime_ns, digest(path)]
    return result


def restore(archive, identity, output, expected):
    """Native age authentication followed by bounded extraction into a new directory."""
    archive, identity, output = map(safe, (archive, identity, output))
    require(re.fullmatch('[0-9a-f]{64}', expected) and digest(archive) == expected, 'selected archive changed')
    require(not output.exists(), 'restore destination exists; existing vault preserved')
    private(output.parent)
    with tempfile.TemporaryDirectory(prefix='.restore-', dir=output.parent) as temporary:
        work = Path(temporary)
        plain = work / 'archive.tar.gz'
        # Do not parse any plaintext until age has authenticated the entire stream.
        run(['age', '--decrypt', '--identity', identity, '--output', plain, archive], timeout=600)
        plain.chmod(0o600)
        ready = private(work / 'ready')
        seen, total = set(), 0
        with tarfile.open(plain, 'r:gz') as source:
            for member in source:
                name = PurePosixPath(member.name)
                require(not name.is_absolute() and '..' not in name.parts and name.parts[:1] == ('data',)
                        and '\\' not in member.name and '\x00' not in member.name, 'unsafe backup path')
                require(name not in seen and len(seen) < 100000, 'duplicate or excessive backup entries')
                seen.add(name)
                require(member.isdir() or member.isfile(), 'backup links and special files are refused')
                total += member.size
                require(0 <= member.size <= 8 * 1024**3 and total <= 32 * 1024**3, 'backup expansion limit exceeded')
                target = ready.joinpath(*name.parts[1:])
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                else:
                    require(target != ready, 'invalid backup root')
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with target.open('xb') as dest, source.extractfile(member) as origin:
                        os.fchmod(dest.fileno(), 0o600)
                        shutil.copyfileobj(origin, dest, 1024 * 1024)
                        dest.flush()
                        os.fsync(dest.fileno())
        counts = database(ready)
        ready.rename(output)
        sync(output.parent)
    return {'archive_sha256': expected, 'database': counts}


class Service:
    def __init__(self, configuration):
        self.file = safe(configuration)
        self.config = json.loads(self.file.read_text())
        require(self.config.get('schema') == 1, 'invalid service configuration')
        self.root = private(Path(self.config['state']))
        self.data = safe(self.root / 'data')
        require(re.fullmatch('vaultwarden/server@sha256:[0-9a-f]{64}', self.config['image']), 'pinned Vaultwarden image required')
        require(re.fullmatch('tailscale/tailscale@sha256:[0-9a-f]{64}', self.config['network_image']), 'pinned network image required')
        self.compose_file = safe(self.root / 'compose.json')

    @contextmanager
    def locked(self):
        with safe(self.root / 'writer.lock').open('a+b') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error('another vault operation is running') from None
            token = HELD_LOCKS.set((*HELD_LOCKS.get(), lock.fileno()))
            try:
                yield
            finally:
                HELD_LOCKS.reset(token)

    def compose(self, *arguments):
        return run(['docker', 'compose', '--project-name', self.config['project'], '--file', self.compose_file, *arguments], timeout=300)

    def prepare(self):
        require(re.fullmatch('[a-z][a-z0-9-]{2,40}', self.config['project']), 'invalid service project name')
        port = self.config.get('port', 8222)
        require(type(port) is int and 1024 <= port <= 65535, 'invalid local port')
        domain = self.config.get('domain', 'http://localhost:' + str(port))
        require(domain == 'http://localhost:' + str(port) or re.fullmatch(r'https://[a-z0-9-]+\.[a-z0-9-]+\.ts\.net', domain), 'invalid private HTTPS domain')
        private(self.root / 'network')
        services = {
            'network': {'image': self.config['network_image'], 'restart': 'unless-stopped',
                'entrypoint': ['tailscaled'], 'command': ['--tun=userspace-networking', '--state=/var/lib/tailscale/tailscaled.state'],
                'volumes': [str(self.root / 'network') + ':/var/lib/tailscale'],
                'ports': ['127.0.0.1:' + str(port) + ':8080'], 'cap_drop': ['ALL'],
                'security_opt': ['no-new-privileges:true']},
            'vaultwarden': {'image': self.config['image'], 'restart': 'unless-stopped',
                'network_mode': 'service:network', 'depends_on': ['network'],
                'environment': {'DOMAIN': domain, 'ROCKET_PORT': '8080', 'SIGNUPS_ALLOWED': 'false',
                                'INVITATIONS_ALLOWED': 'false', 'SHOW_PASSWORD_HINT': 'false'},
                'volumes': [str(self.data) + ':/data'], 'stop_grace_period': '60s',
                'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}}
        desired = {'services': services}
        if self.compose_file.exists():
            require(json.loads(self.compose_file.read_text()) == desired, 'service configuration changed; reconcile it explicitly before starting')
        else:
            save(self.compose_file, desired)

    def inspect(self):
        ids = self.compose('ps', '-aq', 'vaultwarden').decode().split()
        require(len(ids) <= 1, 'ambiguous Vaultwarden service')
        if not ids:
            return None
        value = json.loads(run(['docker', 'inspect', ids[0]]))[0]
        require(value['Config']['Image'] == self.config['image'], 'running service image changed')
        mounts = [m for m in value['Mounts'] if m['Destination'] == '/data']
        require(len(mounts) == 1 and mounts[0]['Type'] == 'bind' and mounts[0]['RW']
                and mounts[0]['Source'] == str(self.data), 'service data owner changed')
        return value

    def healthy(self):
        deadline = time.monotonic() + 60
        while True:
            value = self.inspect()
            require(value and value['State']['Running'], 'Vaultwarden is not running')
            try:
                run(['docker', 'exec', value['Id'], '/healthcheck.sh'])
                return
            except Error:
                require(time.monotonic() < deadline, 'Vaultwarden health check timed out')
                time.sleep(1)

    def on(self):
        with self.locked():
            require(not (self.root / 'capture-pending.json').exists(), 'interrupted capture requires recovery')
            database(self.data)
            self.prepare()
            self.compose('up', '-d', '--no-recreate')
            self.healthy()
            return {'state': 'running', 'url': self.config.get('domain', 'http://localhost:' + str(self.config.get('port', 8222)))}

    def off(self):
        with self.locked():
            self.prepare()
            self.compose('stop', '--timeout', '60')
            value = self.inspect()
            require(value is None or not value['State']['Running'], 'service did not stop')
            return {'state': 'stopped', 'data': 'retained'}

    def status(self):
        self.prepare()
        value = self.inspect()
        return {'state': 'running' if value and value['State']['Running'] else 'stopped',
                'health': (value or {}).get('State', {}).get('Health', {}).get('Status', 'not checked'),
                'url': self.config.get('domain'), 'backup_pending': (self.root / 'capture-pending.json').exists()}

    def keepalive(self):
        """Keep this WSL session attached while the Windows operator runs the vault."""
        with safe(self.root / 'windows-session.lock').open('a+b') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return {'session': 'already attached'}
            inactive = None
            while True:
                try:
                    value = self.inspect()
                    active = bool(value and value['State']['Running']) or (self.root / 'capture-pending.json').exists()
                except (Error, OSError, subprocess.SubprocessError):
                    active = False
                if active:
                    inactive = None
                elif inactive is None:
                    inactive = time.monotonic()
                elif time.monotonic() - inactive >= 30:
                    return {'session': 'stopped'}
                time.sleep(5)

    def exclusive(self, identifier):
        for other in run(['docker', 'ps', '-aq', '--no-trunc']).decode().split():
            if other == identifier:
                continue
            value = json.loads(run(['docker', 'inspect', other]))[0]
            for mount in value['Mounts']:
                if mount['Type'] == 'bind' and mount['RW']:
                    path = Path(mount['Source']).resolve()
                    require(path != self.data and path not in self.data.parents and self.data not in path.parents,
                            'another container has write access to vault data')

    def same(self, record):
        value = self.inspect()
        require(value and value['Id'] == record['container'] and value['Image'] == record['image_id']
                and value['Mounts'] == record['mounts'], 'capture service identity changed; manual recovery required')
        return value

    def stopped(self, record):
        value = self.same(record)
        state = value['State']
        require(state['Status'] == 'exited' and not state['Running'] and not state.get('OOMKilled')
                and state['ExitCode'] == 0 and state['StartedAt'] == record['started_at'], 'graceful capture barrier failed')
        self.exclusive(value['Id'])

    def resume(self, record):
        value = self.same(record)
        if not record['was_running']:
            require(not value['State']['Running'] and value['State']['StartedAt'] == record['started_at'], 'stopped service changed')
            return
        if value['State']['Running']:
            require(record['phase'] == 'RESUMING' or (record['phase'] == 'STOPPING'
                    and value['State']['StartedAt'] == record['started_at']), 'unexpected running service')
        else:
            require(value['State']['Status'] == 'exited' and value['State']['StartedAt'] == record['started_at'], 'service lifecycle changed')
            record['phase'] = 'RESUMING'
            save(self.root / 'capture-pending.json', record)
            run(['docker', 'start', value['Id']])
        self.healthy()

    def recover(self):
        with self.locked():
            journal = safe(self.root / 'capture-pending.json')
            require(journal.is_file(), 'no interrupted capture')
            self.resume(json.loads(journal.read_text()))
            journal.unlink()
            sync(self.root)
            return {'capture': 'discarded', 'service': 'restored to its previous running/stopped state'}

    def backup(self):
        with self.locked():
            self.prepare()
            journal = safe(self.root / 'capture-pending.json')
            require(not journal.exists(), 'interrupted capture requires recovery')
            owner = self.inspect()
            require(owner and owner['State']['Status'] in ('running', 'exited') and not owner['State'].get('Paused'), 'service is not ready for capture')
            self.exclusive(owner['Id'])
            recipient = safe(self.config['recipient'])
            recipient_hash = digest(recipient)
            record = {'container': owner['Id'], 'image_id': owner['Image'], 'mounts': owner['Mounts'],
                      'started_at': owner['State']['StartedAt'], 'was_running': owner['State']['Running'], 'phase': 'STOPPING'}
            backups = private(self.root / 'backups')
            save(journal, record)
            try:
                if record['was_running']:
                    run(['docker', 'stop', '--time', '60', owner['Id']])
                self.stopped(record)
                record['phase'] = 'CAPTURING'
                save(journal, record)
                with tempfile.TemporaryDirectory(prefix='.capture-', dir=self.root) as temporary:
                    work = Path(temporary)
                    before = inventory(self.data)
                    copied = private(work / 'data')
                    for relative in before:
                        if relative in ('db.sqlite3', 'db.sqlite3-wal', 'db.sqlite3-shm'):
                            continue
                        target = copied / relative
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        shutil.copyfile(self.data / relative, target)
                        target.chmod(0o600)
                    with closing(sqlite3.connect((self.data / 'db.sqlite3').as_uri() + '?mode=ro', uri=True)) as source, \
                            closing(sqlite3.connect(copied / 'db.sqlite3')) as target:
                        source.backup(target)
                    counts = database(copied)
                    archive = work / 'archive.tar.gz'
                    with tarfile.open(archive, 'w:gz') as tar:
                        tar.add(copied, arcname='data', recursive=True)
                    encrypted = work / 'archive.age'
                    run(['age', '--recipients-file', recipient, '--output', encrypted, archive], timeout=600)
                    encrypted.chmod(0o600)
                    require(inventory(self.data) == before and digest(recipient) == recipient_hash, 'capture inputs changed')
                    self.stopped(record)
                    self.resume(record)
                    name = 'vaultwarden-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex + '.tar.gz.age'
                    with encrypted.open('rb') as stream:
                        os.fsync(stream.fileno())
                    checksum = digest(encrypted)
                    encrypted.rename(backups / name)
                    sync(backups)
                    receipt = {'archive': name, 'sha256': checksum, 'image': self.config['image'], 'database': counts,
                               'created_at': datetime.now(timezone.utc).isoformat(), 'service_resumed': record['was_running']}
                    save(backups / (name + '.json'), receipt)
                journal.unlink()
                sync(self.root)
                return receipt
            except BaseException:
                try:
                    self.resume(record)
                except BaseException:
                    pass  # Keep the durable journal; never certify an interrupted capture.
                else:
                    journal.unlink()
                    sync(self.root)
                raise

    def publish(self, receipt):
        """Append ciphertext only, with a non-forced parent-bound Git ref update."""
        repository = self.config['backup_repository']
        branch = self.config['backup_branch']
        require(re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'invalid private repository')
        require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9/_.-]*', branch) and '..' not in branch, 'invalid backup branch')
        gh = self.config.get('github_cli', 'gh')
        def api(path, data=None, method=None):
            args = [gh, 'api', 'repos/' + repository + ('/' + path if path else '')]
            if method:
                args += ['--method', method]
            payload = None
            if data is not None:
                args += ['--input', '-']
                payload = json.dumps(data).encode()
            result = subprocess.run(args, input=payload, capture_output=True, timeout=120)
            require(result.returncode == 0, 'private backup API failed at ' + path.split('/')[0] + '; local encrypted backup retained')
            return json.loads(result.stdout)
        info = api('')
        require(info.get('private') is True and info.get('full_name', '').lower() == repository.lower(), 'backup requires the selected private repository')
        archive = safe(self.root / 'backups' / receipt['archive'])
        require(archive.parent == self.root / 'backups' and archive.is_file() and archive.stat().st_size <= 64 * 1024**2,
                'cloud backup accepts up to 64 MiB; local encrypted backup retained')
        require(digest(archive) == receipt['sha256'], 'local encrypted backup changed')
        raw = archive.read_bytes()
        require(raw.startswith(b'age-encryption.org/v1\n'), 'only native age ciphertext can be published')
        ref = 'heads/' + quote(branch, safe='/')
        parent = api('git/ref/' + ref)['object']['sha']
        tree = api('git/commits/' + parent)['tree']['sha']
        prefix = 'frankenstein/vaultwarden/backups/' + receipt['sha256'] + '/'
        metadata = {k: receipt[k] for k in ('sha256', 'image', 'created_at')}
        metadata.update(schema=1, format='vaultwarden-native-age-tar')
        entries = []
        for name, content in [('vault.tar.gz.age', raw), ('backup.json', (json.dumps(metadata, sort_keys=True) + '\n').encode())]:
            blob = api('git/blobs', {'content': base64.b64encode(content).decode(), 'encoding': 'base64'})['sha']
            expected = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
            require(blob == expected, 'GitHub blob digest differs')
            entries.append({'path': prefix + name, 'mode': '100644', 'type': 'blob', 'sha': blob})
        created_tree = api('git/trees', {'base_tree': tree, 'tree': entries})['sha']
        author = {'name': 'Frankenstein backup', 'email': 'frankenstein@localhost'}
        commit = api('git/commits', {'message': 'Back up encrypted Vaultwarden state', 'tree': created_tree,
                                   'parents': [parent], 'author': author, 'committer': author})['sha']
        require(api('git/ref/' + ref)['object']['sha'] == parent, 'private branch changed; retry publication')
        api('git/refs/' + ref, {'sha': commit, 'force': False}, method='PATCH')
        downloaded = base64.b64decode(api('git/blobs/' + entries[0]['sha'])['content'])
        require(hashlib.sha256(downloaded).hexdigest() == receipt['sha256'], 'cloud download verification failed')
        result = {'commit': commit, 'sha256': receipt['sha256'], 'repository': repository, 'branch': branch, 'download_verified': True}
        save(self.root / 'last-published.json', result)
        return result

    def cloud_backup(self):
        return self.publish(self.backup())

    def connect(self, replace_address=False):
        with self.locked():
            require(not (self.root / 'capture-pending.json').exists(), 'interrupted capture requires recovery')
            self.prepare()
            network = json.loads(self.compose('exec', '-T', 'network', 'tailscale', 'status', '--json'))
            require(network['BackendState'] == 'Running', 'sign in to Tailscale on this PC first')
            domain = 'https://' + network['Self']['DNSName'].rstrip('.')
            require(re.fullmatch(r'https://[a-z0-9-]+\.[a-z0-9-]+\.ts\.net', domain), 'unexpected private network domain')
            require(not self.config.get('domain') or self.config['domain'] == domain or replace_address,
                    'existing Vault address differs; retain its network identity or explicitly select --replace-address')
            self.compose('exec', '-T', 'network', 'tailscale', 'serve', '--bg', '--https=443', 'http://127.0.0.1:8080')
            if self.config.get('domain') != domain:
                previous = json.loads(self.compose_file.read_text())
                save(self.root / ('compose-before-' + uuid.uuid4().hex + '.json'), previous)
                self.config['domain'] = domain
                save(self.file, self.config)
                previous['services']['vaultwarden']['environment']['DOMAIN'] = domain
                save(self.compose_file, previous)
                self.prepare()
                self.compose('up', '-d', '--no-deps', '--force-recreate', 'vaultwarden')
            self.healthy()
            return {'state': 'running', 'url': domain}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('on', 'off', 'status', 'backup', 'cloud-backup', 'recover', 'keepalive'):
        commands.add_parser(action)
    commands.add_parser('connect').add_argument('--replace-address', action='store_true')
    recovery = commands.add_parser('restore')
    for option in ('archive', 'identity', 'output'):
        recovery.add_argument('--' + option, type=Path, required=True)
    recovery.add_argument('--sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == 'restore':
            result = restore(args.archive, args.identity, args.output, args.sha256)
        else:
            require(args.config is not None, 'service configuration required')
            service = Service(args.config)
            result = service.connect(args.replace_address) if args.action == 'connect' else getattr(service, args.action.replace('-', '_'))()
        print(json.dumps(result))
        return 0
    except (Error, OSError, ValueError, KeyError, sqlite3.Error, tarfile.TarError, subprocess.SubprocessError) as error:
        print('VAULT=FAIL (' + (str(error) if isinstance(error, Error) else type(error).__name__) + ')')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
