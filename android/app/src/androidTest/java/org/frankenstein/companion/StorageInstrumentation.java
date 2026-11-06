package org.frankenstein.companion;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.Arrays;

/** Exercises the real device Keystore and private storage with random dummy data. */
public final class StorageInstrumentation extends Instrumentation {
    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); start(); }
    @Override public void onStart() {
        Bundle result = new Bundle();
        File created = null;
        try {
            byte[] bytes = new byte[2 * 1024 * 1024 + 41];
            new SecureRandom().nextBytes(bytes);
            String id = Identity.hex(MessageDigest.getInstance("SHA-256").digest(bytes));
            created = new File(getTargetContext().getNoBackupFilesDir(), "objects/" + id + ".encrypted");
            if (created.exists()) throw new AssertionError("Unexpected fixture collision");
            LocalStorage.open(getTargetContext()).put(id, bytes.length, new ByteArrayInputStream(bytes));
            // Reopen the encrypted keyset using this device's real AndroidKeyStore.
            BlobStore reopened = LocalStorage.open(getTargetContext());
            reopened.verify(id);
            try (DataInputStream stream = reopened.open(id)) {
                if (stream.readLong() != bytes.length) throw new AssertionError("Length mismatch");
                byte[] restored = new byte[bytes.length];
                stream.readFully(restored);
                if (!Arrays.equals(bytes, restored) || stream.read() != -1) throw new AssertionError("Content mismatch");
            }
            byte[] encrypted = Files.readAllBytes(created.toPath());
            encrypted[encrypted.length - 1] ^= 1;
            Files.write(created.toPath(), encrypted);
            boolean rejected = false;
            try { reopened.verify(id); } catch (IOException | GeneralSecurityException expected) { rejected = true; }
            if (!rejected) throw new AssertionError("Tampered object accepted");
            result.putString("result", "PASS: AndroidKeyStore persistence, streaming roundtrip, directory sync, tamper rejection");
            finish(Activity.RESULT_OK, result);
        } catch (Exception | AssertionError error) {
            result.putString("result", "FAIL: " + error.getClass().getSimpleName() + ": " + error.getMessage());
            finish(Activity.RESULT_CANCELED, result);
        } finally {
            if (created != null) created.delete(); // Only this random test object.
        }
    }
}
