package org.frankenstein.companion;

import com.google.crypto.tink.StreamingAead;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.nio.channels.FileChannel;
import java.security.MessageDigest;

/** Immutable content-addressed objects, encrypted before touching app storage. */
final class BlobStore {
    static final long MAX_BYTES = 8L * 1024 * 1024 * 1024;
    private final File root;
    private final StreamingAead cipher;
    BlobStore(File root, StreamingAead cipher) throws IOException {
        this.root = root;
        this.cipher = cipher;
        if (!root.isDirectory() && !root.mkdirs()) throw new IOException("Private storage unavailable");
        File[] unfinished = root.listFiles((dir, name) -> name.endsWith(".partial"));
        if (unfinished != null) for (File file : unfinished) Files.delete(file.toPath());
    }
    private File path(String id) throws IOException {
        if (!id.matches("[0-9a-f]{64}")) throw new IOException("Invalid object id");
        return new File(root, id + ".encrypted");
    }
    private byte[] aad(String id) { return ("frankenstein-object-v1:" + id).getBytes(StandardCharsets.US_ASCII); }
    synchronized void put(String id, long length, InputStream input) throws Exception {
        File target = path(id);
        if (length < 0 || length > MAX_BYTES || root.getUsableSpace() < length + 16 * 1024 * 1024) throw new IOException("Object exceeds storage limit");
        File temporary = File.createTempFile("receive-", ".partial", root);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (FileOutputStream file = new FileOutputStream(temporary)) {
                // Tink owns streaming segmentation, nonces, authentication and keys.
                OutputStream encrypted = cipher.newEncryptingStream(new FilterOutputStream(file) {
                    @Override public void close() throws IOException { flush(); }
                }, aad(id));
                DataOutputStream data = new DataOutputStream(encrypted);
                data.writeLong(length);
                copy(input, data, length, digest);
                data.close();
                file.getFD().sync();
            }
            if (!Identity.hex(digest.digest()).equals(id)) throw new IOException("Object checksum mismatch");
            if (target.exists()) {
                // A retry is idempotent only if the retained complete object verifies.
                verify(id);
            } else {
                Files.move(temporary.toPath(), target.toPath());
                try (FileChannel directory = FileChannel.open(root.toPath(), StandardOpenOption.READ)) {
                    directory.force(true);
                }
            }
        } finally { Files.deleteIfExists(temporary.toPath()); }
    }
    DataInputStream open(String id) throws Exception {
        FileInputStream file = new FileInputStream(path(id));
        try { return new DataInputStream(cipher.newDecryptingStream(file, aad(id))); }
        catch (Exception e) { file.close(); throw e; }
    }
    void verify(String id) throws Exception {
        try (DataInputStream input = open(id)) {
            long length = input.readLong();
            if (length < 0 || length > MAX_BYTES) throw new IOException("Invalid object length");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            copy(input, new OutputStream() {
                @Override public void write(int ignored) { }
                @Override public void write(byte[] bytes, int offset, int count) { }
            }, length, digest);
            if (input.read() != -1 || !Identity.hex(digest.digest()).equals(id)) throw new IOException("Object failed verification");
        }
    }
    static void copy(InputStream input, OutputStream output, long size, MessageDigest digest) throws IOException {
        byte[] buffer = new byte[65536];
        while (size > 0) {
            int count = input.read(buffer, 0, (int)Math.min(buffer.length, size));
            if (count < 0) throw new EOFException("Transfer disconnected");
            digest.update(buffer, 0, count);
            output.write(buffer, 0, count);
            size -= count;
        }
    }
}
