"""Stage a selected stable native engine release; never consume a branch as an update."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

REPOSITORY = 'Asyraf2003/frankenstein'
WORKFLOW = 'https://github.com/' + REPOSITORY + '/.github/workflows/release.yml@refs/heads/main'


class Error(Exception):
    pass


def gh(*args):
    result = subprocess.run(['gh', *args], text=True, capture_output=True)
    if result.returncode:
        raise Error('GitHub release/provenance operation failed; no update staged')
    return result.stdout


def api(path):
    return json.loads(gh('api', 'repos/' + REPOSITORY + '/' + path))


def attest(path, commit=None):
    args = ['attestation', 'verify', str(path), '--repo', REPOSITORY,
            '--cert-identity', WORKFLOW, '--source-ref', 'refs/heads/main']
    if commit:
        args += ['--source-digest', commit]
    gh(*args)


def validate_manifest(value, tag):
    if not isinstance(value, dict) or set(value) != {'version', 'commit', 'packages'}:
        raise Error('invalid release manifest')
    if value['version'] != tag[1:] or not isinstance(value['commit'], str) or not re.fullmatch('[0-9a-f]{40}', value['commit']):
        raise Error('release version/commit mismatch')
    packages = value['packages']
    if not isinstance(packages, dict) or len(packages) != 2:
        raise Error('release must include core and Openbox')
    roles = set()
    for name, digest in packages.items():
        match = re.fullmatch(r'frankenstein-(core|openbox)-' + re.escape(value['version']) + r'-[1-9][0-9]*-any\.pkg\.tar\.zst', name)
        if not match or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise Error('invalid package name or checksum')
        roles.add(match.group(1))
    if roles != {'core', 'openbox'}:
        raise Error('release must include both distinct engine packages')
    return value


def stage(tag, destination):
    if not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', tag):
        raise Error('select an exact stable vMAJOR.MINOR.PATCH release')
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise Error('destination already exists')
    if not destination.parent.is_dir():
        raise Error('destination parent does not exist')
    release = api('releases/tags/' + tag)
    if release.get('draft') is not False or release.get('prerelease') is not False or release.get('tag_name') != tag:
        raise Error('draft, experimental or mismatched release refused')
    assets = [a.get('name') for a in release.get('assets', [])]
    if assets.count('engine.json') != 1:
        raise Error('release manifest missing or ambiguous')
    # Atomic publication: failures leave no directory that a provisioner could mistake for ready.
    with tempfile.TemporaryDirectory(prefix='.frankenstein-release-', dir=destination.parent) as temporary:
        root = Path(temporary)
        def download(name):
            gh('release', 'download', tag, '--repo', REPOSITORY, '--pattern', name, '--dir', str(root))
            path = root / name
            if path.is_symlink() or not path.is_file():
                raise Error('release asset missing or not a regular file')
            return path
        manifest_path = download('engine.json')
        attest(manifest_path)
        manifest = validate_manifest(json.loads(manifest_path.read_text()), tag)
        ref = api('git/ref/tags/' + tag)['object']
        for _ in range(4):
            if ref['type'] == 'commit':
                break
            if ref['type'] != 'tag':
                raise Error('release tag does not reference a commit')
            ref = api('git/tags/' + ref['sha'])['object']
        if ref['type'] != 'commit' or ref['sha'] != manifest['commit']:
            raise Error('release tag and attested source do not match')
        if api('compare/' + manifest['commit'] + '...main')['status'] not in ('ahead', 'identical'):
            raise Error('release source has not been integrated into main')
        attest(manifest_path, manifest['commit'])
        for name, expected in manifest['packages'].items():
            if assets.count(name) != 1:
                raise Error('release package missing or ambiguous')
            path = download(name)
            with path.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                    raise Error('release package digest mismatch')
            attest(path, manifest['commit'])
        # Rename the fully verified sibling directory; no partial package installation here.
        root.rename(destination)
    return destination


def main(args):
    parser = argparse.ArgumentParser(prog='frankenstein engine')
    parser.add_argument('action', choices=['stage'])
    parser.add_argument('tag')
    parser.add_argument('directory', type=Path)
    opts = parser.parse_args(args)
    try:
        print('Verified stable engine staged: ' + str(stage(opts.tag, opts.directory)))
        return 0
    except (Error, OSError, ValueError, KeyError) as error:
        print('ERROR: ' + str(error))
        return 2
