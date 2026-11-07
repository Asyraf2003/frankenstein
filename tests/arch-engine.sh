#!/usr/bin/env bash
# Native transaction proof with locally built fixtures, never a published release.
set -euo pipefail
[[ -f /.dockerenv && ${FRANKENSTEIN_DISPOSABLE:-} == 1 ]] || exit 77
# Copy package inputs only; local Android/Gradle output and Git history are not inputs.
mkdir -p /engine-fixture/vault
for input in bootstrap bin lib profiles assets tests packaging licenses installer transport VERSION LICENSE; do
    cp -R "/source/$input" "/engine-fixture/"
done
cp /source/vault/*.py /engine-fixture/vault/
python - <<'PY'
from pathlib import Path
root = Path('/engine-fixture')
p = root / 'packaging/PKGBUILD'
p.write_text(p.read_text().replace('pkgver=0.2.0', 'pkgver=0.2.1'))
(root / 'VERSION').write_text('0.2.1\n')
with (root / 'lib/control.py').open('a') as f:
    f.write('\nENGINE_FIXTURE_MARKER = "new-generation"\n')
PY
chown -R builder:builder /engine-fixture
runuser -u builder -- bash -c 'cd /engine-fixture/packaging && makepkg --nodeps --nocheck'
python /source/tests/native-engine-update.py
