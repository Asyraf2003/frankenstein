import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location('usb', Path(__file__).resolve().parents[1] / 'transport' / 'usb.py')
usb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(usb)
OPENSSL = shutil.which('openssl') or ('C:/Program Files/Git/usr/bin/openssl.exe' if os.name == 'nt' else None)


class Transfer(unittest.TestCase):
    def exchange(self, operation, response):
        client, server = socket.socketpair()
        client.settimeout(5)
        server.settimeout(5)
        errors = []
        def serve():
            try:
                with server:
                    response(server)
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=serve)
        worker.start()
        try:
            with client:
                return operation(client)
        finally:
            worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
            if errors:
                raise errors[0]

    def test_push_receipt_and_content(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'source'
            source.write_bytes(os.urandom(200000))
            def receiver(sock):
                self.assertEqual(usb.read_exact(sock, 5), b'FRK1\x01')
                expected = usb.read_exact(sock, 32)
                length = struct.unpack('>Q', usb.read_exact(sock, 8))[0]
                data = usb.read_exact(sock, length)
                self.assertEqual(expected, hashlib.sha256(data).digest())
                sock.sendall(b'\0')
            self.assertEqual(self.exchange(lambda sock: usb.push(sock, source), receiver), usb.digest(source))

    def test_pull_atomic_and_disconnect(self):
        for valid, ending in ((True, True), (False, True), (True, False)):
            with self.subTest(valid=valid, ending=ending), tempfile.TemporaryDirectory() as folder:
                data = os.urandom(20000)
                identifier = hashlib.sha256(data).hexdigest()
                target = Path(folder) / 'received'
                def sender(sock):
                    self.assertEqual(usb.read_exact(sock, 37), b'FRK1\x02' + bytes.fromhex(identifier))
                    sock.sendall(b'\0' + struct.pack('>Q', len(data)))
                    sock.sendall(data if valid else b'x' * len(data))
                    if ending:
                        sock.sendall(b'\0')
                if valid and ending:
                    self.exchange(lambda sock: usb.pull(sock, identifier, target), sender)
                    self.assertEqual(target.read_bytes(), data)
                else:
                    with self.assertRaises((ValueError, EOFError)):
                        self.exchange(lambda sock: usb.pull(sock, identifier, target), sender)
                    self.assertFalse(target.exists())
                    self.assertEqual(list(Path(folder).iterdir()), [])

    def test_existing_destination_and_git_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'existing'
            target.write_text('preserve')
            with self.assertRaises(FileExistsError):
                usb.pull(None, '0' * 64, target)
            self.assertEqual(target.read_text(), 'preserve')
            (Path(folder) / '.git').mkdir()
            with self.assertRaises(ValueError):
                usb.private_directory(Path(folder) / 'state')

    @unittest.skipUnless(OPENSSL, 'native OpenSSL required')
    def test_native_mutual_tls_and_wrong_device(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            client_key, client_cert = usb.identity(root / 'client', OPENSSL)
            phone_key, phone_cert = usb.identity(root / 'phone', OPENSSL)
            wrong_key, wrong_cert = usb.identity(root / 'wrong', OPENSSL)
            phone_der = ssl.PEM_cert_to_DER_cert(phone_cert.read_text())
            for accepted in (True, False):
                with self.subTest(accepted=accepted):
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    context.load_cert_chain(phone_cert, phone_key)
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.load_verify_locations(client_cert)
                    listener = socket.socket()
                    listener.bind(('127.0.0.1', 0))
                    listener.listen(1)
                    listener.settimeout(5)
                    result = []
                    def peer():
                        with listener:
                            raw, _ = listener.accept()
                            try:
                                with context.wrap_socket(raw, server_side=True) as secured:
                                    secured.sendall(b'approved')
                                    result.append(True)
                            except ssl.SSLError:
                                result.append(False)
                            finally:
                                raw.close()
                    thread = threading.Thread(target=peer)
                    thread.start()
                    try:
                        with usb.connect(listener.getsockname()[1], client_key if accepted else wrong_key,
                                         client_cert if accepted else wrong_cert, phone_der) as secured:
                            self.assertEqual(usb.read_exact(secured, 8), b'approved')
                            self.assertTrue(accepted)
                    except (OSError, EOFError):
                        self.assertFalse(accepted)
                    finally:
                        thread.join(6)
                    self.assertEqual(result, [accepted])


if __name__ == '__main__':
    unittest.main()
