#!/usr/bin/env bash
# Execute only inside the disposable Arch container created by tests/container.sh.
set -euo pipefail
[[ -f /.dockerenv && ${FRANKENSTEIN_DISPOSABLE:-} == 1 ]] || exit 77
pacman -Syu --noconfirm --needed base-devel python sudo networkmanager bluez bluez-utils
useradd -m -s /bin/bash builder
printf 'builder ALL=(root) NOPASSWD: /usr/bin/pacman\n' > /etc/sudoers.d/frankenstein-test-builder
chmod 0440 /etc/sudoers.d/frankenstein-test-builder
cp -R /source /build
chown -R builder:builder /build
runuser -u builder -- bash -c 'cd /build && printf "\n\n\n\n" | ./bootstrap core'
pacman -Qkk frankenstein-core
frankenstein --help
frankenstein packages status
runuser -u builder -- bash -c 'printf "\n" | frankenstein packages install tree'
tree --version
runuser -u builder -- bash -c 'printf "\n" | frankenstein packages remove tree'
if pacman -Q tree; then echo 'package removal failed' >&2; exit 1; fi
if pacman -Q frankenstein-openbox; then echo 'core pulled in the desktop' >&2; exit 1; fi
useradd -m -s /bin/bash tester
runuser -u tester -- frankenstein profile status
runuser -u tester -- frankenstein profile apply shell --replace
runuser -u tester -- frankenstein profile verify
runuser -u tester -- bash --noprofile --norc -ic 'source ~/.bashrc; command -v frankenstein; [[ $PS1 == *"\\u@\\h"* ]]'
pacman -S --noconfirm --needed zoxide fzf
runuser -u tester -- bash --noprofile --norc -ic 'source ~/.bashrc && declare -F z && declare -F fzf-file-widget && declare -F _fzf_complete'
runuser -u tester -- frankenstein profile rollback
runuser -u tester -- frankenstein profile verify
# Native providers must fail honestly without a system bus; never power the host.
if frankenstein wifi status; then echo 'unexpected network daemon in isolated container' >&2; exit 1; fi
if frankenstein power status; then echo 'unexpected system manager in isolated container' >&2; exit 1; fi
systemctl --root=/ enable NetworkManager.service bluetooth.service
test -L /etc/systemd/system/multi-user.target.wants/NetworkManager.service
test -L /etc/systemd/system/bluetooth.target.wants/bluetooth.service
systemctl --root=/ disable NetworkManager.service bluetooth.service
printf 'ARCH_CORE_PROOF=PASS\n'
