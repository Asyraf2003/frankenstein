"""Use the paired phone's Google authorization for native, scoped rclone bisync."""
import argparse
import configparser
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
PROVIDERS = ROOT if (ROOT / 'vault').is_dir() else ROOT.parent
sys.path.insert(0, str(PROVIDERS / 'vault'))
import recovery_kit as kit

FOLDERS = ('downloads', 'media', 'documents')
MARKER = '.frankenstein-drive-access'


class Error(ValueError):
    pass


def run(*args):
    result = subprocess.run(['rclone', *map(str, args)], capture_output=True, text=True)
    if result.returncode:
        # Native errors can contain account data and private filenames.
        raise Error('Drive provider failed; authorization or a new baseline may be required')
    return result.stdout


def write(path, value):
    path = kit.safe(path)
    temporary = path.with_name(path.name + '.tmp')
    kit.safe(temporary)
    with open(temporary, 'w', opener=lambda p, flags: os.open(p, flags, 0o600)) as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


@contextmanager
def locked(state):
    state = kit.outside_git(state)
    kit.private_directories(state)
    with (state / 'lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error('Drive sync is already running') from None
        yield state


def phone_credentials(ecosystem):
    state = kit.outside_git(ecosystem) / 'state'
    path = kit.safe(state / 'credentials/google-drive.json')
    if not path.is_file():
        raise Error('Connect Google Drive on the paired phone first; no PC login is needed')
    if path.stat().st_size > 65536:
        raise Error('Invalid Google authorization record')
    credential = kit.decode(path.read_bytes())
    profile = kit.decode(kit.safe(state / 'desired/user.json').read_bytes())
    email = profile.get('google_email', '')
    if not email or credential.get('account', '').casefold() != email.casefold():
        raise Error('Google authorization does not match the account selected on the phone')
    if credential.get('schema') != 1 or not credential.get('refresh_token') or not credential.get('access_token'):
        raise Error('Phone Google authorization needs offline access')
    for key in ('access_token', 'refresh_token', 'client_secret', 'expiry'):
        value = credential.get(key, '')
        if not isinstance(value, str) or any(c in value for c in '\r\n\0'):
            raise Error('Invalid Google authorization record')
    if not re.fullmatch(r'[A-Za-z0-9._-]+\.apps\.googleusercontent\.com', credential.get('client_id', '')):
        raise Error('Invalid Google OAuth client')
    return credential


def import_credentials(state, credential):
    token = {k: credential[k] for k in ('access_token', 'refresh_token', 'expiry') if k in credential}
    token['token_type'] = 'Bearer'
    config = configparser.ConfigParser(interpolation=None)
    config['google'] = {'type': 'drive', 'scope': 'drive', 'client_id': credential['client_id'],
                        'client_secret': credential.get('client_secret', ''),
                        'token': json.dumps(token), 'use_trash': 'true', 'skip_gdocs': 'true'}
    import io
    output = io.StringIO()
    config.write(output)
    write(state / 'rclone.conf', output.getvalue())


def common(state, folder_id=None):
    options = ['--config', str(state / 'rclone.conf'), '--drive-skip-gdocs', '--drive-use-trash']
    if folder_id:
        options += ['--drive-root-folder-id', folder_id]
    return options


def mypc(state):
    folders = json.loads(run('lsjson', 'google:', '--dirs-only', *common(state)))
    matches = [item for item in folders if item.get('Name') == 'mypc']
    if not matches:
        run('mkdir', 'google:mypc', *common(state))
        folders = json.loads(run('lsjson', 'google:', '--dirs-only', *common(state)))
        matches = [item for item in folders if item.get('Name') == 'mypc']
    if len(matches) != 1 or not re.fullmatch(r'[A-Za-z0-9_-]+', matches[0].get('ID', '')):
        raise Error('Drive mypc folder is missing or ambiguous; existing data was not selected')
    return matches[0]['ID']


def initial_conflicts(local, remote, options):
    listings = []
    for path in (local, remote):
        entries = json.loads(run('lsjson', path, '--recursive', '--files-only', '--hash', *options))
        paths = {}
        for entry in entries:
            name = entry['Path']
            if name in paths:
                raise Error('Duplicate Drive names need resolution before sync')
            paths[name] = entry
        listings.append(paths)
    left, right = listings
    for name in left.keys() & right.keys():
        if name == MARKER:
            continue
        a, b = left[name], right[name]
        digest = a.get('Hashes', {}).get('md5')
        if not digest or digest != b.get('Hashes', {}).get('md5') or a['Size'] != b['Size']:
            raise Error('Existing local and Drive files differ; resolve the conflict before initial sync')


def pair(local, remote, work, local_backup, remote_backup, options, initialize=False):
    if initialize:
        initial_conflicts(local, remote, options)
    args = ['bisync', str(local), remote, '--workdir', str(work),
            '--check-access', '--check-filename', MARKER, '--compare', 'size,modtime,checksum',
            '--conflict-resolve', 'none', '--conflict-loser', 'num', '--max-delete', '50',
            '--backup-dir1', str(local_backup), '--backup-dir2', remote_backup,
            '--resilient', '--recover', *options]
    if initialize:
        args += ['--resync', '--resync-mode', 'path2']
    run(*args)


def sync(state, initialize=False):
    selection = kit.decode((state / 'selection.json').read_bytes())
    base = kit.outside_git(Path(selection['local']))
    options = common(state, selection['folder_id'])
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    # Verify every baseline conflict before changing any selected folder.
    if initialize:
        for name in FOLDERS:
            if (state / (name + '.ready')).is_file():
                continue
            local = kit.safe(base / name)
            local.mkdir(parents=True, exist_ok=True)
            run('mkdir', 'google:' + name, *options)
            initial_conflicts(local, 'google:' + name, options)
    for name in FOLDERS:
        local = kit.safe(base / name)
        ready = state / (name + '.ready')
        if not initialize and not ready.is_file():
            raise Error('Drive baseline is incomplete; scheduled sync remains stopped')
        first = initialize and not ready.is_file()
        if first:
            (local / MARKER).touch(mode=0o600, exist_ok=True)
            run('copyto', local / MARKER, 'google:' + name + '/' + MARKER, *options)
        pair(local, 'google:' + name, state / 'bisync' / name,
             state / 'history' / name / stamp,
             'google:.frankenstein-history/' + name + '/' + stamp, options, first)
        if first:
            write(ready, 'verified\n')


def main(argv=None):
    home = Path.home()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'setup', 'sync', 'on', 'off'))
    parser.add_argument('--state', type=Path, default=home / '.local/state/frankenstein/drive')
    parser.add_argument('--ecosystem', type=Path, default=home / '.local/state/frankenstein/ecosystem')
    parser.add_argument('--local', type=Path, default=home)
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare':
            for name in FOLDERS:
                kit.safe(args.local / name).mkdir(mode=0o700, parents=True, exist_ok=True)
            if not kit.safe(args.ecosystem / 'state/credentials/google-drive.json').is_file():
                print('Drive folders ready; waiting for authorization from the paired phone')
                return 0
        if args.action in ('on', 'off'):
            command = 'enable' if args.action == 'on' else 'disable'
            subprocess.run(['systemctl', '--user', command, '--now', 'frankenstein-drive.timer'], check=True)
            return 0
        with locked(args.state) as state:
            if args.action in ('prepare', 'setup'):
                credential = phone_credentials(args.ecosystem)
                credential_digest = hashlib.sha256(json.dumps(credential, sort_keys=True).encode()).hexdigest()
                local = kit.outside_git(args.local)
                kit.private_directories(local)
                if (state / 'selection.json').exists():
                    selection = kit.decode((state / 'selection.json').read_bytes())
                    if selection['account'].casefold() != credential['account'].casefold() or selection['local'] != str(local):
                        raise Error('Existing Drive selection belongs to another account or home directory')
                    # Preserve rclone's refreshed tokens on ordinary retries,
                    # but accept a new authorization supplied by the phone.
                    if selection.get('credential_sha256') != credential_digest:
                        import_credentials(state, credential)
                        selection['credential_sha256'] = credential_digest
                        write(state / 'selection.json', json.dumps(selection))
                else:
                    import_credentials(state, credential)
                    selection = {'schema': 1, 'account': credential['account'],
                                 'folder_id': mypc(state), 'local': str(local), 'credential_sha256': credential_digest}
                    write(state / 'selection.json', json.dumps(selection))
                sync(state, initialize=True)
            else:
                sync(state)
        print('DRIVE_SYNC=VERIFIED')
        if args.action == 'prepare':
            subprocess.run(['systemctl', '--user', 'enable', '--now', 'frankenstein-drive.timer'], check=True)
        return 0
    except (Error, OSError, ValueError, subprocess.CalledProcessError) as error:
        print('DRIVE_SYNC=FAIL: ' + (str(error) if isinstance(error, Error) else type(error).__name__), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
