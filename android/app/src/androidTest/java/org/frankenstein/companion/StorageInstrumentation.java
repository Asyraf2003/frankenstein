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
            byte[] fixture;
            try (InputStream input = getContext().getAssets().open("portable.fpe")) {
                ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (bytesOut.size() + count > 4 * 1024 * 1024) throw new AssertionError("Fixture too large");
                    bytesOut.write(buffer, 0, count);
                }
                fixture = bytesOut.toByteArray();
            }
            NativeVault vault = new NativeVault(getTargetContext());
            org.json.JSONObject opened = vault.inspect(new ByteArrayInputStream(fixture), fixture.length, "desired/profile.json");
            byte[] profile = android.util.Base64.decode(opened.getJSONObject("selected").getString("base64"), android.util.Base64.NO_WRAP);
            if (!new String(profile, java.nio.charset.StandardCharsets.UTF_8).contains("\"username\":\"fixture\"")) throw new AssertionError("Native age opening mismatch");
            File scratch = new File(getTargetContext().getNoBackupFilesDir(), "test-portable-" + java.util.UUID.randomUUID());
            if (!scratch.mkdir()) throw new IOException("Cannot reserve fixture directory");
            try {
                android.content.Context isolated = new android.content.ContextWrapper(getTargetContext()) {
                    @Override public File getNoBackupFilesDir() { return scratch; }
                };
                BlobStore isolatedStore = LocalStorage.open(isolated);
                NativeVault isolatedVault = new NativeVault(isolated);
                String selectedId = Identity.hex(MessageDigest.getInstance("SHA-256").digest(fixture));
                isolatedStore.put(selectedId, fixture.length, new ByteArrayInputStream(fixture));
                java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
                java.util.concurrent.ExecutorService writers = java.util.concurrent.Executors.newFixedThreadPool(2);
                try {
                    java.util.concurrent.Callable<Boolean> activate = () -> {
                        start.await();
                        try {
                            new NativeVault(isolated).activate(isolatedStore, selectedId, NativeVault.EMPTY);
                            return true;
                        } catch (IOException expected) {
                            if (!expected.getMessage().startsWith("Vault conflict:")) throw expected;
                            return false;
                        }
                    };
                    java.util.concurrent.Future<Boolean> first = writers.submit(activate);
                    java.util.concurrent.Future<Boolean> second = writers.submit(activate);
                    start.countDown();
                    boolean firstWon = first.get(60, java.util.concurrent.TimeUnit.SECONDS);
                    boolean secondWon = second.get(60, java.util.concurrent.TimeUnit.SECONDS);
                    if (firstWon == secondWon) throw new AssertionError("Exactly one concurrent activation must win");
                } finally { writers.shutdownNow(); }
                if (!isolatedVault.current().equals(selectedId)) throw new AssertionError("Vault selection not retained");
                boolean conflict = false;
                try { isolatedVault.activate(isolatedStore, selectedId, NativeVault.EMPTY); }
                catch (IOException expected) { conflict = true; }
                if (!conflict || !isolatedVault.current().equals(selectedId)) throw new AssertionError("Concurrent selection was overwritten");
            } finally {
                try (java.util.stream.Stream<java.nio.file.Path> paths = Files.walk(scratch.toPath())) {
                    for (java.nio.file.Path path : (Iterable<java.nio.file.Path>) paths.sorted(java.util.Comparator.reverseOrder())::iterator)
                        Files.delete(path);
                }
            }
            fixture[fixture.length - 1] ^= 1;
            rejected = false;
            try { vault.inspect(new ByteArrayInputStream(fixture), fixture.length, null); }
            catch (Exception expected) { rejected = true; }
            if (!rejected) throw new AssertionError("Native age accepted altered fixture");
            result.putString("result", "PASS: AndroidKeyStore persistence, streaming roundtrip, directory sync, tamper rejection, native age opening, final authentication, generation conflict preservation");
            finish(Activity.RESULT_OK, result);
        } catch (Exception | AssertionError error) {
            result.putString("result", "FAIL: " + error.getClass().getSimpleName() + ": " + error.getMessage());
            finish(Activity.RESULT_CANCELED, result);
        } finally {
            if (created != null) created.delete(); // Only this random test object.
        }
    }
}
