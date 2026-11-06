"""User-visible base readiness, with separate provisioning and recovery status."""
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    if not os.environ.get('DISPLAY'):
        raise RuntimeError('Welcome requires a running X11 desktop')
    subprocess.run(['xsetroot', '-solid', '#20242b'], check=True)
    receipt = json.loads(Path('/var/lib/frankenstein/boot.json').read_text())
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if receipt.get('boot_id') != boot or not receipt.get('base_verified'):
        raise RuntimeError('this boot has not passed base verification')
    print('Welcome to Frankenstein ' + receipt['engine'])
    print('Encrypted Arch base boot verified. Openbox desktop is running.')
    print('USB pairing and vault provisioning: not configured.')
    print('LTS recovery entry installed; recovery boot has not yet been verified.')
    print('Use frankenstein --help for native system controls.')
    if sys.stdin.isatty():
        input('\nPress Enter to close.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print('Welcome pending: ' + str(error), file=sys.stderr)
        if sys.stdin.isatty():
            input('Press Enter to close.')
        sys.exit(1)
