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
                TrustedPeers trusted = new TrustedPeers(isolated);
                if (trusted.contains(Identity.certificate())) throw new AssertionError("Unknown peer trusted");
                trusted.remember(Identity.certificate());
                if (!new TrustedPeers(isolated).contains(Identity.certificate())) throw new AssertionError("Trust did not survive reopening");
                trusted.forgetAll();
                if (new TrustedPeers(isolated).contains(Identity.certificate())) throw new AssertionError("Revoked peer trusted");
                Files.write(new File(scratch, "trusted-peers").toPath(), new byte[]{1, 2, 3});
                boolean invalidTrust = false;
                try { new TrustedPeers(isolated).contains(Identity.certificate()); }
                catch (IOException expected) { invalidTrust = true; }
                if (!invalidTrust) throw new AssertionError("Corrupt trust pointer accepted");
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
                boolean enrollmentRejected = false;
                try { isolatedVault.enroll(isolatedStore, new org.json.JSONObject()); }
                catch (IOException expected) { enrollmentRejected = true; }
                if (!enrollmentRejected || !isolatedVault.current().equals(selectedId))
                    throw new AssertionError("Enrollment replaced existing state");
            } finally {
                try (java.util.stream.Stream<java.nio.file.Path> paths = Files.walk(scratch.toPath())) {
                    for (java.nio.file.Path path : (Iterable<java.nio.file.Path>) paths.sorted(java.util.Comparator.reverseOrder())::iterator)
                        Files.delete(path);
                }
            }
            File enrollmentScratch = new File(getTargetContext().getNoBackupFilesDir(), "test-enrollment-" + java.util.UUID.randomUUID());
            if (!enrollmentScratch.mkdir()) throw new IOException("Cannot reserve enrollment fixture directory");
            try {
                android.content.Context isolated = new android.content.ContextWrapper(getTargetContext()) {
                    @Override public File getNoBackupFilesDir() { return enrollmentScratch; }
                };
                org.json.JSONObject files = new org.json.JSONObject();
                Enrollment.add(files, "desired/arch.json", new org.json.JSONObject().put("username", "fixture")
                    .put("hostname", "phonecreated").put("timezone", "UTC").put("packages", new org.json.JSONArray()));
                Enrollment.add(files, "credentials/arch-install.json", new org.json.JSONObject()
                    .put("password", "synthetic-account-only").put("disk_passphrase", "synthetic-disk-only"));
                org.json.JSONObject context = new org.json.JSONObject().put("revisions", new org.json.JSONObject()
                    .put("engine", BuildConfig.ENGINE_REVISION).put("state", "0000000000000000000000000000000000000000"))
                    .put("features", new org.json.JSONArray().put("synthetic-phone-enrollment"))
                    .put("required_owners", new org.json.JSONArray().put("desired").put("credentials"));
                org.json.JSONObject request = new org.json.JSONObject().put("context", context).put("files", files)
                    .put("recovery_passphrase", "synthetic-phone-recovery-only-2026");
                BlobStore store = LocalStorage.open(isolated);
                NativeVault enrolled = new NativeVault(isolated);
                String enrolledId = enrolled.enroll(store, request);
                if (!enrolled.current().equals(enrolledId)) throw new AssertionError("Enrollment was not activated");
                File exported = new File(getTargetContext().getExternalFilesDir(null), "enrollment-fixture.zip");
                try (FileOutputStream target = new FileOutputStream(exported)) { BackupExport.write(store, enrolled, enrolledId, target); }
                int count = 0;
                try (java.util.zip.ZipInputStream exportedZip = new java.util.zip.ZipInputStream(new FileInputStream(exported))) {
                    java.util.zip.ZipEntry entry;
                    while ((entry = exportedZip.getNextEntry()) != null) {
                        if (!Arrays.asList("vault.age", "context.json", "selection.json", "recovery/identity.age", "recovery/recipient.txt", "recovery/manifest.json").contains(entry.getName()))
                            throw new AssertionError("Unexpected backup member");
                        count++;
                    }
                }
                if (count != 6) throw new AssertionError("Incomplete ciphertext backup");
                GitHubStorageChecks.run(isolated, store, enrolled);
                File deviceOnly = new File(enrollmentScratch, "without-recovery");
                if (!deviceOnly.mkdir()) throw new IOException("Cannot reserve device-key fixture");
                android.content.Context deviceContext = new android.content.ContextWrapper(getTargetContext()) {
                    @Override public File getNoBackupFilesDir() { return deviceOnly; }
                };
                request.put("recovery_passphrase", "");
                Enrollment.add(files, "credentials/arch-install.json", new org.json.JSONObject()
                    .put("password", "1234").put("disk_passphrase", "synthetic-disk-only"));
                BlobStore deviceStore = LocalStorage.open(deviceContext);
                NativeVault deviceVault = new NativeVault(deviceContext);
                deviceVault.enroll(deviceStore, request);
                GitHubStorageChecks.run(deviceContext, deviceStore, deviceVault, "github-device-key-fixture.zip");
                // Synthetic-only survivor identity fixture, never the active owner vault.
                File survivor = new File(getTargetContext().getExternalFilesDir(null), "github-device-key-fixture.fpe");
                try (DataInputStream input = deviceStore.open(deviceVault.current()); OutputStream output = new FileOutputStream(survivor)) {
                    long length = input.readLong();
                    BlobStore.copy(input, output, length, MessageDigest.getInstance("SHA-256"));
                }
            } finally {
                try (java.util.stream.Stream<java.nio.file.Path> paths = Files.walk(enrollmentScratch.toPath())) {
                    for (java.nio.file.Path path : (Iterable<java.nio.file.Path>) paths.sorted(java.util.Comparator.reverseOrder())::iterator)
                        Files.delete(path);
                }
            }
            fixture[fixture.length - 1] ^= 1;
            rejected = false;
            try { vault.inspect(new ByteArrayInputStream(fixture), fixture.length, null); }
            catch (Exception expected) { rejected = true; }
            if (!rejected) throw new AssertionError("Native age accepted altered fixture");
            result.putString("result", "PASS: AndroidKeyStore, native enrollment/amendment, ciphertext export, GitHub encrypted token rotation/journal recovery and replica refusal");
            finish(Activity.RESULT_OK, result);
        } catch (Exception | AssertionError error) {
            result.putString("result", "FAIL: " + error.getClass().getSimpleName() + ": " + error.getMessage());
            finish(Activity.RESULT_CANCELED, result);
        } finally {
            if (created != null) created.delete(); // Only this random test object.
        }
    }
}
