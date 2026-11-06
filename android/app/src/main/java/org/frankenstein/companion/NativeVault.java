package org.frankenstein.companion;

import android.content.Context;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;

/** Independent native age opening. Plaintext travels only through private pipes. */
final class NativeVault {
    static final String EMPTY = "0000000000000000000000000000000000000000000000000000000000000000";
    private static final Object STATE_LOCK = new Object();
    private final String executable;
    private final AtomicFile active;
    NativeVault(Context context) {
        executable = context.getApplicationInfo().nativeLibraryDir + "/libfrankenstein_vault.so";
        active = new AtomicFile(new File(context.getNoBackupFilesDir(), "active-vault"));
    }
    String current() throws IOException {
        synchronized (STATE_LOCK) { return readCurrent(); }
    }
    private String readCurrent() throws IOException {
        if (!active.getBaseFile().exists() && !new File(active.getBaseFile() + ".bak").exists()) return EMPTY;
        String selected;
        try (InputStream input = active.openRead()) {
            selected = new String(readBounded(input, 64), StandardCharsets.US_ASCII);
        }
        if (!selected.matches("[0-9a-f]{64}")) throw new IOException("Invalid current vault pointer");
        return selected;
    }
    JSONObject activate(BlobStore store, String id, String expected) throws Exception {
        if (!current().equals(expected)) throw new IOException("Vault conflict: selected generation changed");
        JSONObject result = inspect(store, id, null);
        // Activity recreation can leave an earlier server finishing verification.
        // Compare and publish under one lock shared by every NativeVault instance.
        synchronized (STATE_LOCK) {
            if (!readCurrent().equals(expected)) throw new IOException("Vault conflict: selected generation changed");
            FileOutputStream output = null;
            try {
                output = active.startWrite();
                output.write(id.getBytes(StandardCharsets.US_ASCII));
                active.finishWrite(output);
            } catch (Exception error) {
                if (output != null) active.failWrite(output);
                throw error;
            }
        }
        return result;
    }
    JSONObject inspect(BlobStore store, String id, String selected) throws Exception {
        store.verify(id);
        try (DataInputStream input = store.open(id)) {
            long length = input.readLong();
            return inspect(input, length, selected);
        }
    }
    JSONObject inspect(InputStream input, long length, String selected) throws Exception {
        List<String> args = new ArrayList<>();
        args.add(executable);
        args.add(selected == null ? "verify" : "read");
        if (selected != null) args.add(selected);
        return new JSONObject(new String(run(input, length, args, 3 * 1024 * 1024), StandardCharsets.UTF_8));
    }
    String enroll(BlobStore store, JSONObject request) throws Exception {
        if (!current().equals(EMPTY)) throw new IOException("An existing vault must not be replaced by enrollment");
        byte[] input = request.toString().getBytes(StandardCharsets.UTF_8);
        byte[] bundle = null;
        try {
            if (input.length > 2 * 1024 * 1024) throw new IOException("Enrollment exceeds limit");
            bundle = run(new ByteArrayInputStream(input), input.length,
                Arrays.asList(executable, "enroll"), 4 * 1024 * 1024);
            String id = Identity.hex(java.security.MessageDigest.getInstance("SHA-256").digest(bundle));
            store.put(id, bundle.length, new ByteArrayInputStream(bundle));
            activate(store, id, EMPTY);
            return id;
        } finally {
            Arrays.fill(input, (byte)0);
            if (bundle != null) Arrays.fill(bundle, (byte)0);
        }
    }
    private byte[] run(InputStream input, long length, List<String> args, int maximum) throws Exception {
        Process process = new ProcessBuilder(args).start();
        Timer watchdog = new Timer(true);
        watchdog.schedule(new TimerTask() { public void run() { process.destroyForcibly(); } }, 300000);
        FutureTask<Void> producer = new FutureTask<>(() -> {
            try (OutputStream output = process.getOutputStream()) {
                byte[] buffer = new byte[65536];
                long remaining = length;
                while (remaining > 0) {
                    int count = input.read(buffer, 0, (int)Math.min(buffer.length, remaining));
                    if (count < 0) throw new EOFException("Truncated portable vault");
                    output.write(buffer, 0, count);
                    remaining -= count;
                }
                if (input.read() != -1) throw new IOException("Unexpected portable vault suffix");
            }
            return null;
        });
        Thread worker = new Thread(producer, "frankenstein-vault-input");
        worker.start();
        try {
            byte[] result = readBounded(process.getInputStream(), maximum);
            if (!process.waitFor(5, TimeUnit.SECONDS) || process.exitValue() != 0) throw new IOException("Vault verification failed");
            producer.get(5, TimeUnit.SECONDS);
            return result;
        } finally {
            watchdog.cancel();
            process.destroyForcibly();
            process.getOutputStream().close();
            process.getInputStream().close();
            process.getErrorStream().close();
            producer.cancel(true);
        }
    }
    private static byte[] readBounded(InputStream input, int maximum) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = input.read(buffer)) != -1) {
            if (output.size() + count > maximum) throw new IOException("Native result exceeds limit");
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }
}
