#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
: "${ANDROID_HOME:?Android SDK required}"
ndk="$ANDROID_HOME/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin"
[[ -x "$ndk/aarch64-linux-android29-clang" ]] || { echo 'Install Android NDK 28.2.13676358' >&2; exit 1; }
output="$root/android/app/build/generated/native"
mkdir -p "$output/jniLibs" "$output/assets/licenses"
cd "$root/vault/native"
go mod verify
for target in 'arm64-v8a arm64 aarch64-linux-android29' 'armeabi-v7a arm armv7a-linux-androideabi29' 'x86_64 amd64 x86_64-linux-android29'; do
    read -r abi architecture compiler <<< "$target"
    mkdir -p "$output/jniLibs/$abi"
    CGO_ENABLED=1 GOOS=android GOARCH="$architecture" GOARM=7 CC="$ndk/$compiler-clang" \
        go build -buildvcs=false -trimpath -buildmode=pie -ldflags='-s -w' -o "$output/jniLibs/$abi/libfrankenstein_vault.so" .
done
# Ship notices for linked Go dependencies and the Go runtime with the APK.
go list -m -f '{{if .Dir}}{{.Path}} {{.Dir}}{{end}}' all | while read -r module directory; do
    [[ "$module" == github.com/Asyraf2003/frankenstein/vault/native ]] && continue
    if [[ -f "$directory/LICENSE" ]]; then
        install -m644 "$directory/LICENSE" "$output/assets/licenses/${module//\//_}.txt"
    fi
done
install -m644 "$(go env GOROOT)/LICENSE" "$output/assets/licenses/go-runtime.txt"
