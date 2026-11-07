package org.frankenstein.companion;

import android.content.Context;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import org.json.JSONObject;

/** Local trust only; never replicated with a user's portable vault. */
final class TrustedPeers {
    private static final Object LOCK = new Object();
    private final AtomicFile pointer;
    private final BlobStore store;
    TrustedPeers(Context context) throws Exception {
        pointer = new AtomicFile(new File(context.getNoBackupFilesDir(), "trusted-peers"));
        store = LocalStorage.open(context);
    }
    private JSONObject read() throws Exception {
        if (!pointer.getBaseFile().exists() && !new File(pointer.getBaseFile() + ".bak").exists()) return new JSONObject();
        String id;
        try (DataInputStream input = new DataInputStream(pointer.openRead())) {
            byte[] bytes = new byte[64];
            input.readFully(bytes);
            if (input.read() != -1) throw new IOException("Invalid trust pointer");
            id = new String(bytes, StandardCharsets.US_ASCII);
            if (!id.matches("[0-9a-f]{64}")) throw new IOException("Invalid trust pointer");
        }
        store.verify(id);
        try (DataInputStream input = store.open(id)) {
            long length = input.readLong();
            if (length < 2 || length > 65536) throw new IOException("Invalid trust record");
            byte[] content = new byte[(int)length];
            input.readFully(content);
            if (input.read() != -1) throw new IOException("Invalid trust record");
            return new JSONObject(new String(content, StandardCharsets.UTF_8));
        }
    }
    boolean contains(X509Certificate certificate) throws Exception {
        synchronized (LOCK) { return read().has(Identity.fingerprint(certificate)); }
    }
    void remember(X509Certificate certificate) throws Exception {
        synchronized (LOCK) {
            JSONObject peers = read();
            if (peers.length() >= 32 && !peers.has(Identity.fingerprint(certificate))) throw new IOException("Trusted PC limit reached");
            peers.put(Identity.fingerprint(certificate), System.currentTimeMillis());
            write(peers);
        }
    }
    void forgetAll() throws Exception {
        synchronized (LOCK) { write(new JSONObject()); }
    }
    private void write(JSONObject peers) throws Exception {
        byte[] bytes = peers.toString().getBytes(StandardCharsets.UTF_8);
        String id = Identity.hex(MessageDigest.getInstance("SHA-256").digest(bytes));
        store.put(id, bytes.length, new ByteArrayInputStream(bytes));
        FileOutputStream output = null;
        try {
            output = pointer.startWrite();
            output.write(id.getBytes(StandardCharsets.US_ASCII));
            pointer.finishWrite(output);
        } catch (Exception error) {
            if (output != null) pointer.failWrite(output);
            throw error;
        }
    }
}
