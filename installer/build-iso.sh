#!/usr/bin/env bash
# Build on Arch. The output is experimental unless published by release.yml.
set -euo pipefail
[[ $# == 1 && -f /etc/arch-release && $EUID == 0 ]] || {
    echo 'Usage (Arch root): bash installer/build-iso.sh NEW_BUILD_DIRECTORY' >&2; exit 2;
}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ ! -e $1 ]] || { echo 'Build directory must not exist' >&2; exit 2; }
mkdir -p -- "$1"
build=$(cd -- "$1" && pwd -P)
for tool in mkarchiso makepkg runuser python; do command -v "$tool" >/dev/null; done
umask 022
mkdir "$build/source" "$build/out"
cp -R -- "$root/bin" "$root/lib" "$root/profiles" "$root/assets" "$root/tests" \
    "$root/packaging" "$root/licenses" "$root/installer" "$root/vault" "$root/transport" "$root/LICENSE" "$root/VERSION" "$build/source/"
install -Dm644 "$root/android/verify-release.py" "$build/source/android/verify-release.py"
# Package only scripts and configuration. No large compilation or target-side build.
chmod 755 "$build" "$build/source"
chown -R nobody:nobody "$build/source"
runuser -u nobody -- bash -c 'cd -- "$1/packaging"; makepkg --nodeps --cleanbuild' bash "$build/source"
cp -a /usr/share/archiso/configs/releng "$build/profile"
profile="$build/profile"
printf '\npython\nage\nandroid-tools\nopenssl\ngit\ngithub-cli\n' >> "$profile/packages.x86_64"
cat >> "$profile/profiledef.sh" <<'PROFILE'
iso_name="frankenstein-experimental"
iso_publisher="Frankenstein development"
iso_application="Frankenstein Arch live installer (experimental)"
file_permissions["/usr/local/bin/frankenstein-install"]="0:0:755"
file_permissions["/usr/local/bin/frankenstein-usb"]="0:0:755"
file_permissions["/usr/local/bin/frankenstein-provision"]="0:0:755"
PROFILE
payload="$profile/airootfs/opt/frankenstein"
mkdir -p "$payload/packages" "$profile/airootfs/usr/local/bin"
cp "$root/installer/install.py" "$payload/install.py"
mkdir -p "$payload/lib" "$payload/vault" "$payload/transport"
cp "$root/lib/provision.py" "$root/lib/releases.py" "$payload/lib/"
cp "$root/vault/"*.py "$payload/vault/"
cp "$root/transport/usb.py" "$payload/transport/"
cp "$build/source/packaging/"*.pkg.tar.zst "$payload/packages/"
python - "$payload" "$root/VERSION" <<'PY'
import hashlib, json, pathlib, sys
payload = pathlib.Path(sys.argv[1])
packages = {}
for path in sorted((payload/'packages').glob('*.pkg.tar.zst')):
    with path.open('rb') as stream:
        packages[path.name] = hashlib.file_digest(stream, 'sha256').hexdigest()
assert len(packages) == 2
(payload/'packages.json').write_text(json.dumps({'version': pathlib.Path(sys.argv[2]).read_text().strip(), 'packages': packages})+'\n')
PY
cat > "$profile/airootfs/usr/local/bin/frankenstein-install" <<'ENTRY'
#!/bin/sh
exec python /opt/frankenstein/install.py "$@"
ENTRY
cat > "$profile/airootfs/usr/local/bin/frankenstein-usb" <<'ENTRY'
#!/bin/sh
exec python /opt/frankenstein/transport/usb.py "$@"
ENTRY
cat > "$profile/airootfs/usr/local/bin/frankenstein-provision" <<'ENTRY'
#!/bin/sh
exec python /opt/frankenstein/lib/provision.py "$@"
ENTRY
cat > "$profile/airootfs/etc/motd" <<'MOTD'
Frankenstein experimental live installer
List disks: frankenstein-install
Inspect: frankenstein-install --disk /dev/SELECTED_DISK
Install a stable engine: frankenstein-install --disk /dev/SELECTED_DISK --engine-release vMAJOR.MINOR.PATCH --execute
Development test only: frankenstein-install --disk /dev/SELECTED_DISK --experimental-engine --execute
Installation always requires explicit disk approval. No disk is selected automatically.
Install from an enrolled stable companion:
frankenstein-install --disk /dev/SELECTED_DISK --phone USB_SERIAL --engine-release vMAJOR.MINOR.PATCH --execute
Approve the PC fingerprint on your phone. Disk erasure still requires local approval.
MOTD
# Serial is an additional console for disposable VM proof; local display stays usable.
python - "$profile" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
for directory in ('grub', 'efiboot', 'syslinux'):
    for path in (root/directory).rglob('*'):
        if path.is_file() and path.suffix in ('.cfg', '.conf'):
            lines = path.read_text().splitlines()
            for i, line in enumerate(lines):
                if line.lstrip().startswith(('linux ', 'linuxefi ', 'options ', 'APPEND ')) and 'archisobasedir=' in line:
                    lines[i] += ' console=tty0 console=ttyS0,115200n8'
            path.write_text('\n'.join(lines)+'\n')
PY
mkarchiso -v -w "$build/work" -o "$build/out" "$profile"
(cd "$build/out" && sha256sum ./*.iso > SHA256SUMS)
printf 'Experimental image and checksums: %s/out\n' "$build"
