#!/usr/bin/env python3
"""Owner-approved mutual TLS over an authenticated Android ADB USB connection.

ADB carries public pairing certificates and a loopback port, never private keys.
The Android owner must compare the PC fingerprint and approve on the phone.
"""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time

APP = 'org.frankenstein.companion.dev'
MAX_BYTES = 8 * 1024**3


def outside_git(path):
    path = Path(path).absolute()
    if any(parent.is_symlink() or getattr(parent, 'is_junction', lambda: False)()
           for parent in (path, *path.parents)):
        raise ValueError('symlink state path rejected')
    if any((parent / '.git').exists() for parent in (path, *path.parents)):
        raise ValueError('device state must remain outside Git')
    return path


def private_directory(path):
    path = outside_git(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == 'nt':
        owner = subprocess.check_output(['whoami'], text=True).strip()
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', owner + ':(OI)(CI)F'],
                       check=True, stdout=subprocess.DEVNULL)
    else:
        path.chmod(0o700)
    return path


def identity(folder, openssl='openssl'):
    folder = private_directory(folder)
    key, cert = folder / 'device.key', folder / 'device.pem'
    outside_git(key)
    outside_git(cert)
    if key.exists() != cert.exists():
        raise ValueError('incomplete device identity; preserve and repair it before proceeding')
    if not key.exists():
        with tempfile.TemporaryDirectory(prefix='.identity-', dir=folder) as temporary:
            work = Path(temporary)
            subprocess.run([openssl, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                            '-nodes', '-days', '3650', '-subj', '/CN=Frankenstein device',
                            '-keyout', str(work / 'key'), '-out', str(work / 'cert')],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (work / 'key').chmod(0o600)
            # Exclusive publication: never rotate a device identity implicitly.
            for source, target in ((work / 'key', key), (work / 'cert', cert)):
                with target.open('xb') as out:
                    out.write(source.read_bytes())
                    out.flush()
                    os.fsync(out.fileno())
                target.chmod(0o600)
    return key, cert


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_exact(stream, count):
    data = bytearray()
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise EOFError('USB transfer interrupted')
        data.extend(chunk)
    return bytes(data)


def connect(port, key, cert, phone_der):
    # Use OpenSSL's TLS implementation with the explicitly selected certificate
    # as trust anchor, then compare the exact DER certificate as well.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False  # Device identity is the certificate, not localhost.
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(phone_der))
    context.verify_flags = ssl.VERIFY_X509_PARTIAL_CHAIN
    context.load_cert_chain(cert, key)
    raw = socket.create_connection(('127.0.0.1', port), timeout=60)
    try:
        secured = context.wrap_socket(raw, server_hostname=None)
        if secured.getpeercert(binary_form=True) != phone_der:
            secured.close()
            raise ValueError('phone identity changed')
        return secured
    except BaseException:
        raw.close()
        raise


def push(stream, source):
    source = Path(source)
    size = source.stat().st_size
    if not source.is_file() or not 0 <= size <= MAX_BYTES:
        raise ValueError('invalid transfer size')
    identifier = digest(source)
    stream.sendall(b'FRK1' + b'\x01' + bytes.fromhex(identifier) + struct.pack('>Q', size))
    checked = hashlib.sha256()
    with source.open('rb') as file:
        remaining = size
        while remaining:
            chunk = file.read(min(65536, remaining))
            if not chunk:
                raise ValueError('source changed during transfer')
            checked.update(chunk)
            stream.sendall(chunk)
            remaining -= len(chunk)
        if file.read(1) or checked.hexdigest() != identifier:
            raise ValueError('source changed during transfer')
    if read_exact(stream, 1) != b'\0':
        raise ValueError('receiver did not verify transfer')
    return identifier


def pull(stream, identifier, destination):
    if len(identifier) != 64 or any(c not in '0123456789abcdef' for c in identifier):
        raise ValueError('invalid object digest')
    destination = outside_git(destination)
    if destination.exists():
        raise FileExistsError(destination)
    private_directory(destination.parent)
    stream.sendall(b'FRK1' + b'\x02' + bytes.fromhex(identifier))
    if read_exact(stream, 1) != b'\0':
        raise ValueError('object not available')
    size = struct.unpack('>Q', read_exact(stream, 8))[0]
    if size > MAX_BYTES or shutil.disk_usage(destination.parent).free < size + 16 * 1024**2:
        raise ValueError('object exceeds storage limit')
    descriptor, name = tempfile.mkstemp(prefix='.receive-', dir=destination.parent)
    temporary = Path(name)
    try:
        checked = hashlib.sha256()
        with os.fdopen(descriptor, 'wb') as out:
            remaining = size
            while remaining:
                chunk = read_exact(stream, min(65536, remaining))
                checked.update(chunk)
                out.write(chunk)
                remaining -= len(chunk)
            out.flush()
            os.fsync(out.fileno())
        if read_exact(stream, 1) != b'\0' or checked.hexdigest() != identifier:
            raise ValueError('received object failed integrity verification')
        # Hard-link publication is exclusive on both Windows NTFS and Linux.
        os.link(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return identifier


def current(stream):
    stream.sendall(b'FRK1\x03' + bytes(32))
    if read_exact(stream, 1) != b'\0':
        raise ValueError('phone current vault unavailable')
    identifier = read_exact(stream, 64).decode('ascii')
    if len(identifier) != 64 or any(c not in '0123456789abcdef' for c in identifier):
        raise ValueError('invalid current vault response')
    return identifier


def activate(stream, identifier, previous='0' * 64):
    if any(len(value) != 64 or any(c not in '0123456789abcdef' for c in value)
           for value in (identifier, previous)):
        raise ValueError('invalid vault generation')
    stream.sendall(b'FRK1\x04' + bytes.fromhex(identifier) + bytes.fromhex(previous))
    if read_exact(stream, 1) != b'\0':
        raise ValueError('vault verification or generation conflict')
    return identifier


def receive(usb, key, cert, phone, destination):
    """Receive one selected vault generation, rejecting a concurrent switch."""
    destination = outside_git(destination)
    if destination.exists():
        raise FileExistsError(destination)
    private_directory(destination.parent)
    port = usb.forward()
    try:
        with tempfile.TemporaryDirectory(prefix='.provision-', dir=destination.parent) as temporary:
            selected = Path(temporary) / 'vault.fpe'
            with connect(port, key, cert, phone) as stream:
                identifier = current(stream)
            if identifier == '0' * 64:
                raise ValueError('phone has no provisioned vault')
            with connect(port, key, cert, phone) as stream:
                pull(stream, identifier, selected)
            with connect(port, key, cert, phone) as stream:
                if current(stream) != identifier:
                    raise ValueError('phone vault changed during transfer; retry')
            os.link(selected, destination)
        return identifier
    finally:
        usb.remove(port)


class USB:
    def __init__(self, adb, serial, app=APP):
        self.command = [str(adb), '-s', serial]
        self.app = app

    def run(self, *args):
        return subprocess.check_output([*self.command, *args], stderr=subprocess.PIPE)

    def request(self, cert):
        der = ssl.PEM_cert_to_DER_cert(Path(cert).read_text())
        print('Compare this PC fingerprint on the phone:', hashlib.sha256(der).hexdigest(), flush=True)
        self.run('shell', 'am', 'start', '-n', self.app + '/org.frankenstein.companion.MainActivity',
                 '--es', 'peer_certificate', base64.b64encode(der).decode())

    def phone_certificate(self):
        return self.run('exec-out', 'content', 'read', '--uri', 'content://' + self.app + '.identity/certificate')

    def forward(self):
        return int(self.run('forward', 'tcp:0', 'tcp:48173').strip())

    def remove(self, port):
        self.run('forward', '--remove', 'tcp:' + str(port))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--serial', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--openssl', default='openssl')
    parser.add_argument('--app', default=APP)
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('pair')
    commands.add_parser('current')
    receive_command = commands.add_parser('receive')
    receive_command.add_argument('destination', type=Path)
    select = commands.add_parser('activate')
    select.add_argument('sha256')
    select.add_argument('--previous', default='0' * 64)
    put = commands.add_parser('push')
    put.add_argument('source', type=Path)
    get = commands.add_parser('pull')
    get.add_argument('sha256')
    get.add_argument('destination', type=Path)
    args = parser.parse_args()
    key, cert = identity(args.state, args.openssl)
    usb = USB(args.adb, args.serial, args.app)
    pin = args.state / ('phone-' + hashlib.sha256(args.serial.encode()).hexdigest() + '.der')
    outside_git(pin)
    if args.action == 'pair':
        usb.request(cert)
        phone = usb.phone_certificate()
        # Parse before creating the pin, and never overwrite an existing identity.
        ssl.PEM_cert_to_DER_cert(ssl.DER_cert_to_PEM_cert(phone))
        if pin.exists() and pin.read_bytes() != phone:
            raise ValueError('phone identity changed; explicit device replacement required')
        port = usb.forward()
        try:
            print('Waiting up to 5 minutes for owner approval on the phone.', flush=True)
            deadline = time.monotonic() + 300
            while True:
                try:
                    with connect(port, key, cert, phone) as stream:
                        # A zero-byte object is harmless and confirms the server has
                        # completed client authentication and accepted app traffic.
                        empty = hashlib.sha256(b'').digest()
                        stream.sendall(b'FRK1\x01' + empty + struct.pack('>Q', 0))
                        if read_exact(stream, 1) != b'\0':
                            raise ValueError('pairing proof rejected')
                    break
                except (OSError, EOFError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError('owner approval not received')
                    time.sleep(2)
            if not pin.exists():
                with pin.open('xb') as out:
                    out.write(phone)
            print('PAIRING=VERIFIED', flush=True)
        finally:
            usb.remove(port)
        return
    if not pin.exists():
        raise ValueError('pair this phone before transferring state')
    if args.action == 'receive':
        selected = receive(usb, key, cert, pin.read_bytes(), args.destination)
        print('TRANSFER=VERIFIED\nSHA256=' + selected)
        return
    port = usb.forward()
    try:
        with connect(port, key, cert, pin.read_bytes()) as stream:
            if args.action == 'push':
                selected = push(stream, args.source)
            elif args.action == 'pull':
                selected = pull(stream, args.sha256, args.destination)
            elif args.action == 'activate':
                selected = activate(stream, args.sha256, args.previous)
            else:
                selected = current(stream)
        print('TRANSFER=VERIFIED\nSHA256=' + selected)
    finally:
        usb.remove(port)


if __name__ == '__main__':
    main()
