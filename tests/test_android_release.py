import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

spec = importlib.util.spec_from_file_location('android_release', Path(__file__).resolve().parents[1] / 'android/verify-release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class CompanionRelease(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.apk = Path(self.folder.name) / 'companion.apk'
        self.signer = 'ab' * 32
        self.revision = 'cd' * 20
        self.metadata = dict(schema=1, version='0.2.0', version_code=2000, commit=self.revision,
                             channel='stable', application_id='org.frankenstein.companion')
        self.signature = 'Verified using v2 scheme (APK Signature Scheme v2): true\nSigner #1 certificate SHA-256 digest: ' + self.signer + '\n'
        self.badging = "package: name='org.frankenstein.companion' versionCode='2000' versionName='0.2.0' platformBuildVersionName='15'\n"
        self.write_apk()

    def write_apk(self, copies=1):
        with warnings.catch_warnings(), zipfile.ZipFile(self.apk, 'w') as archive:
            warnings.simplefilter('ignore', UserWarning)
            for _ in range(copies):
                archive.writestr('assets/engine.json', json.dumps(self.metadata))

    def verify(self, proof=False):
        with patch.object(release, 'native', side_effect=[self.signature, self.badging]):
            return release.verify(self.apk, Path('/sdk'), '0.2.0', self.revision, self.signer, proof)

    def test_pinned_production_release(self):
        result = self.verify()
        self.assertEqual(result['commit'], self.revision)
        self.assertEqual(result['signer_sha256'], self.signer)
        self.assertEqual(len(result['sha256']), 64)

    def test_wrong_or_multiple_signers(self):
        for signature in (self.signature.replace(self.signer, 'ef' * 32), self.signature + 'Signer #2 certificate SHA-256 digest: ' + self.signer + '\n'):
            with self.subTest(signature=signature):
                self.signature = signature
                with self.assertRaisesRegex(ValueError, 'signer differs'):
                    self.verify()

    def test_requires_modern_signature(self):
        self.signature = self.signature.replace(': true', ': false')
        with self.assertRaisesRegex(ValueError, 'v2/v3'):
            self.verify()

    def test_rejects_debuggable_or_wrong_package_version(self):
        original = self.badging
        for badging in (original + 'application-debuggable\n', original.replace("'2000'", "'1'"), original.replace("'0.2.0'", "'0.1.0'"), original.replace("companion'", "companion.dev'")):
            with self.subTest(badging=badging):
                self.badging = badging
                with self.assertRaises(ValueError):
                    self.verify()

    def test_rejects_wrong_revision_or_channel(self):
        for key, value in [('commit', '00' * 20), ('channel', 'signing-test')]:
            with self.subTest(key=key):
                previous = self.metadata[key]
                self.metadata[key] = value
                self.write_apk()
                with self.assertRaisesRegex(ValueError, 'source identity'):
                    self.verify()
                self.metadata[key] = previous

    def test_missing_or_duplicate_identity(self):
        for copies in (0, 2):
            self.write_apk(copies)
            with self.assertRaisesRegex(ValueError, 'missing or ambiguous'):
                self.verify()

    def test_proof_is_explicit_and_isolated(self):
        self.metadata.update(channel='signing-test', application_id='org.frankenstein.companion.dev.releaseproof')
        self.write_apk()
        self.badging = self.badging.replace("companion'", "companion.dev.releaseproof'").replace("'0.2.0'", "'0.2.0-signing-test'")
        with self.assertRaisesRegex(ValueError, 'application/version'):
            self.verify()
        self.assertEqual(self.verify(proof=True)['channel'], 'signing-test')

    def test_provider_failure_is_not_trusted(self):
        with patch.object(release.subprocess, 'run') as run:
            run.return_value.returncode = 1
            with self.assertRaisesRegex(ValueError, 'provider failed'):
                release.native(['/sdk/apksigner', 'verify', self.apk])


if __name__ == '__main__':
    unittest.main()
