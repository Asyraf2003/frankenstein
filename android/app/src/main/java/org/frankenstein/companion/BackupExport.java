package org.frankenstein.companion;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.*;
import org.json.JSONObject;

/** Ciphertext-only export with optional recovery capsule; never exports the device key. */
final class BackupExport {
    static void write(BlobStore store, NativeVault vault, String id, OutputStream target) throws Exception {
        vault.inspect(store, id, null);
        try (DataInputStream input = store.open(id); ZipOutputStream zip = new ZipOutputStream(target)) {
            long length = input.readLong();
            if (input.readInt() != 0x46504531) throw new IOException("Invalid vault header");
            int size = input.readInt();
            if (size <= 0 || size > 65536 || length < size + 8L) throw new IOException("Invalid vault header");
            byte[] header = new byte[size];
            input.readFully(header);
            JSONObject parsed;
            try { parsed = new JSONObject(new String(header, StandardCharsets.UTF_8)); }
            finally { java.util.Arrays.fill(header, (byte)0); }
            // Explicit allowlist: do not serialize parsed, which contains a raw key.
            boolean hasRecovery = !parsed.isNull("recovery");
            if (hasRecovery) {
            JSONObject recovery = parsed.getJSONObject("recovery");
            for (String name : new String[]{"identity.age", "recipient.txt", "manifest.json"}) {
                byte[] content = android.util.Base64.decode(recovery.getString(name), android.util.Base64.NO_WRAP);
                entry(zip, "recovery/" + name, content);
            }
            }
            entry(zip, "context.json", parsed.getJSONObject("context").toString().getBytes(StandardCharsets.UTF_8));
            JSONObject selection = new JSONObject().put("schema", hasRecovery ? 1 : 2)
                .put("archive_sha256", parsed.getString("archive_sha256"))
                .put("recovery_manifest_sha256", parsed.get("recovery_manifest_sha256"));
            entry(zip, "selection.json", selection.toString().getBytes(StandardCharsets.UTF_8));
            zip.putNextEntry(new ZipEntry("vault.age"));
            java.security.MessageDigest hash = java.security.MessageDigest.getInstance("SHA-256");
            BlobStore.copy(input, zip, length - 8L - size, hash);
            if (input.read() != -1 || !Identity.hex(hash.digest()).equals(parsed.getString("archive_sha256")))
                throw new IOException("Vault changed during export");
            zip.closeEntry();
            zip.finish();
        }
    }
    private static void entry(ZipOutputStream zip, String name, byte[] content) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(content);
        zip.closeEntry();
    }
}
