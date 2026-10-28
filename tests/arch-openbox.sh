#!/usr/bin/env bash
set -euo pipefail
[[ -f /.dockerenv && ${FRANKENSTEIN_DISPOSABLE:-} == 1 ]] || exit 77
pacman -Syu --noconfirm --needed base-devel python sudo xorg-server-xvfb xdotool wmctrl xorg-xprop libpulse
useradd -m -s /bin/bash builder
printf 'builder ALL=(root) NOPASSWD: /usr/bin/pacman\n' > /etc/sudoers.d/frankenstein-test-builder
chmod 0440 /etc/sudoers.d/frankenstein-test-builder
cp -R /source /build
chown -R builder:builder /build
runuser -u builder -- bash -c 'cd /build && printf "\n\n\n\n" | ./bootstrap openbox'
pacman -Qkk frankenstein-core frankenstein-openbox
useradd -m -s /bin/bash tester
runuser -u tester -- frankenstein profile apply shell --replace
runuser -u tester -- frankenstein profile apply openbox
runuser -u tester -- frankenstein profile verify
runuser -u tester -- dbus-run-session -- python /source/tests/native-openbox.py
runuser -u tester -- frankenstein profile rollback
runuser -u tester -- frankenstein profile verify
test ! -e /home/tester/.xinitrc
test ! -e /home/tester/.config/openbox/rc.xml
printf 'ARCH_OPENBOX_PROOF=PASS\n'
