"""Verify a signed companion before it can enter a versioned release."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile


def require(value, reason):
    if not value:
        raise ValueError(reason)


def native(command):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=120)
    require(result.returncode == 0, 'Android verification provider failed: ' + Path(str(command[0])).name)
    return result.stdout


def verify(apk, tools, version, revision, signer, proof=False):
    require(re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version), 'invalid release version')
    major, minor, patch = map(int, version.split('.'))
    code = major * 1000000 + minor * 1000 + patch
    require(minor <= 999 and patch <= 999 and 1 <= code <= 2100000000, 'invalid Android version code')
    require(re.fullmatch('[0-9a-f]{40}', revision) and re.fullmatch('[0-9a-fA-F]{64}', signer), 'explicit revision and signer required')
    require(apk.is_file() and not apk.is_symlink(), 'APK must be a regular file')
    signatures = native([tools / 'apksigner', 'verify', '--verbose', '--print-certs', apk])
    certificates = re.findall(r'^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$', signatures, re.M)
    require(len(certificates) == 1 and certificates[0].lower() == signer.lower(), 'release signer differs from pinned identity')
    require(re.search(r'^Verified using v[23] scheme .*: true$', signatures, re.M), 'APK v2/v3 signature required')
    badging = native([tools / 'aapt', 'dump', 'badging', apk])
    package = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", badging, re.M)
    app = 'org.frankenstein.companion' + ('.dev.releaseproof' if proof else '')
    require(package and package.groups() == (app, str(code), version + ('-signing-test' if proof else '')), 'APK application/version mismatch')
    require('application-debuggable' not in badging, 'debuggable APK cannot be released')
    expected = {'schema': 1, 'version': version, 'version_code': code, 'commit': revision,
                'channel': 'signing-test' if proof else 'stable', 'application_id': app}
    with zipfile.ZipFile(apk) as archive:
        require(archive.namelist().count('assets/engine.json') == 1, 'APK release identity missing or ambiguous')
        require(archive.getinfo('assets/engine.json').file_size <= 8192, 'APK release identity too large')
        require(json.loads(archive.read('assets/engine.json')) == expected, 'APK source identity mismatch')
    with apk.open('rb') as stream:
        checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {**expected, 'sha256': checksum, 'signer_sha256': signer.lower(), 'apk': apk.name}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--signer', required=True, help='public pinned certificate SHA256, never a password')
    parser.add_argument('--proof', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.apk, args.tools, args.version, args.revision, args.signer, args.proof), sort_keys=True))
    except (ValueError, OSError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        parser.exit(1, 'Companion release rejected: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
