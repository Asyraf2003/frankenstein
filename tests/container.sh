#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
engine=${CONTAINER_ENGINE:-docker}
command -v "$engine" >/dev/null
# No host devices, sockets, credentials or home mounted. Source is read-only.
exec "$engine" run --rm --env FRANKENSTEIN_DISPOSABLE=1 \
    --mount "type=bind,src=$root,dst=/source,readonly" \
    archlinux:base bash /source/tests/arch-core.sh
