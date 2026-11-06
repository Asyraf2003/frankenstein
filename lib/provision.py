"""Restore a paired phone's complete portable state into a fresh private directory."""
import argparse
from pathlib import Path
import hashlib
import sys
import tempfile

# Source checkout and installed package share the same adjacent provider layout.
ROOT = Path(__file__).resolve().parent
PROVIDERS = ROOT if (ROOT / 'vault').is_dir() else ROOT.parent
sys.path.insert(0, str(PROVIDERS / 'vault'))
sys.path.insert(0, str(PROVIDERS / 'transport'))
import recovery_kit as kit
import portable
import usb


def receive(adb, serial, state, output, openssl='openssl', app=usb.APP):
    output = kit.outside_git(output)
    kit.require(not output.exists(), 'PROVISION_DESTINATION_EXISTS')
    state = kit.outside_git(state)
    pin = state / ('phone-' + hashlib.sha256(serial.encode()).hexdigest() + '.der')
    kit.require(pin.is_file(), 'PAIR_THIS_PHONE_FIRST')
    key, cert = usb.identity(state, openssl)
    phone = kit.safe(pin).read_bytes()
    kit.private_directories(output.parent)
    with tempfile.TemporaryDirectory(prefix='.provision-', dir=output.parent) as temporary:
        work = Path(temporary)
        bundle = work / 'received.fpe'
        selected = usb.receive(usb.USB(adb, serial, app), key, cert, phone, bundle)
        ready = work / 'ready'
        context = portable.restore(bundle, ready, selected)
        kit.publish_directory(ready, output)
    return {'sha256': selected, 'context': context}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial', required=True)
    parser.add_argument('--state', type=Path, required=True, help='private paired device identity directory')
    parser.add_argument('--output', type=Path, required=True, help='new private directory outside Git')
    parser.add_argument('--openssl', default='openssl')
    parser.add_argument('--app', default=usb.APP)
    args = parser.parse_args(argv)
    try:
        result = receive(args.adb, args.serial, args.state, args.output, args.openssl, args.app)
        print('PROVISION=VERIFIED\nSHA256=' + result['sha256'])
    except (OSError, ValueError, EOFError) as error:
        # Provider exceptions can include private paths; no payload or credentials.
        print('PROVISION=FAIL (' + (str(error) if isinstance(error, kit.KitError) else type(error).__name__) + ')', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
