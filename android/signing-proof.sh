#!/usr/bin/env bash
# Exercise real APK signing with a disposable identity and isolated application ID.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
: "${ANDROID_HOME:?Android SDK required}"
private=$(mktemp -d)
trap 'rm -rf -- "$private"' EXIT
chmod 700 "$private"
export ANDROID_RELEASE_KEYSTORE="$private/proof.p12"
export ANDROID_RELEASE_STORE_PASSWORD
ANDROID_RELEASE_STORE_PASSWORD=$(openssl rand -hex 32)
export ANDROID_RELEASE_KEY_PASSWORD="$ANDROID_RELEASE_STORE_PASSWORD"
export ANDROID_RELEASE_KEY_ALIAS=fixture
keytool -genkeypair -noprompt -keystore "$ANDROID_RELEASE_KEYSTORE" -storetype PKCS12 \
    -storepass:env ANDROID_RELEASE_STORE_PASSWORD -keypass:env ANDROID_RELEASE_KEY_PASSWORD \
    -alias "$ANDROID_RELEASE_KEY_ALIAS" -keyalg RSA -keysize 3072 -validity 2 \
    -dname 'CN=Disposable Frankenstein signing proof' >/dev/null 2>&1
keytool -exportcert -keystore "$ANDROID_RELEASE_KEYSTORE" -storepass:env ANDROID_RELEASE_STORE_PASSWORD \
    -alias "$ANDROID_RELEASE_KEY_ALIAS" -file "$private/certificate.der" >/dev/null 2>&1
export ANDROID_RELEASE_SIGNER_SHA256
ANDROID_RELEASE_SIGNER_SHA256=$(sha256sum "$private/certificate.der" | cut -d' ' -f1)
revision=$(git -C "$root" rev-parse HEAD)
version=$(cat "$root/VERSION")
bash "$root/android/gradlew" -p "$root/android" --no-daemon :app:assembleRelease -PsigningProof=true "-PengineRevision=$revision"
apk="$root/android/app/build/outputs/apk/release/app-release.apk"
verify=(python3 "$root/android/verify-release.py" --apk "$apk" --tools "$ANDROID_HOME/build-tools/35.0.0" --version "$version" --revision "$revision" --proof)
"${verify[@]}" --signer "$ANDROID_RELEASE_SIGNER_SHA256"
if "${verify[@]}" --signer "$(printf '%064d' 0)" >"$private/rejection.log" 2>&1; then
    echo 'Wrong signer was accepted' >&2; exit 1
fi
grep -q 'release signer differs' "$private/rejection.log"
if env -u ANDROID_RELEASE_KEYSTORE bash "$root/android/gradlew" -p "$root/android" --no-daemon :app:prepareReleaseIdentity -PsigningProof=true >"$private/rejection.log" 2>&1; then
    echo 'Missing signing inputs were accepted' >&2; exit 1
fi
grep -q 'Explicit Android release signing inputs are required' "$private/rejection.log"
if env -u FRANKENSTEIN_RELEASE_AUTHORIZED bash "$root/android/gradlew" -p "$root/android" --no-daemon :app:prepareReleaseIdentity >"$private/rejection.log" 2>&1; then
    echo 'Production signing without authorization was accepted' >&2; exit 1
fi
grep -q 'Production signing requires explicit authorization' "$private/rejection.log"
python3 - "$apk" "$private/tampered.apk" <<'PY'
from pathlib import Path
import shutil
import sys
import zipfile
shutil.copyfile(sys.argv[1], sys.argv[2])
with zipfile.ZipFile(sys.argv[2], 'a') as archive:
    archive.writestr('tampered.txt', b'changed after signing')
PY
if python3 "$root/android/verify-release.py" --apk "$private/tampered.apk" --tools "$ANDROID_HOME/build-tools/35.0.0" \
    --version "$version" --revision "$revision" --signer "$ANDROID_RELEASE_SIGNER_SHA256" --proof >"$private/rejection.log" 2>&1; then
    echo 'Modified APK was accepted' >&2; exit 1
fi
grep -q 'verification provider failed: apksigner' "$private/rejection.log"
echo 'PASS: real isolated APK signature; wrong signer, modified APK, missing key and unauthorized production signing rejected'
