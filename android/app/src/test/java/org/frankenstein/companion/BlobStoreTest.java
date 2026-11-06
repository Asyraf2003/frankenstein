package org.frankenstein.companion;

import com.google.crypto.tink.*;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class BlobStoreTest {
    @Rule public TemporaryFolder temporary = new TemporaryFolder();
    private BlobStore store;
    private File root;
    private StreamingAead cipher;
    @Before public void setup() throws Exception {
        StreamingAeadConfig.register();
        cipher = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM_HKDF_1MB")).getPrimitive(StreamingAead.class);
        root = temporary.newFolder();
        store = new BlobStore(root, cipher);
    }
    private String id(byte[] bytes) throws Exception { return Identity.hex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    @Test public void largeRoundTripAndAtRestEncryption() throws Exception {
        byte[] bytes = new byte[3 * 1024 * 1024 + 23];
        new java.security.SecureRandom().nextBytes(bytes);
        String id = id(bytes);
        store.put(id, bytes.length, new ByteArrayInputStream(bytes));
        store.verify(id);
        try (DataInputStream input = store.open(id)) {
            assertEquals(bytes.length, input.readLong());
            byte[] restored = new byte[bytes.length];
            input.readFully(restored);
            assertArrayEquals(bytes, restored);
            assertEquals(-1, input.read());
        }
        byte[] stored = Files.readAllBytes(new File(root, id + ".encrypted").toPath());
        assertFalse(Arrays.equals(Arrays.copyOf(bytes, 100), Arrays.copyOf(stored, 100)));
    }
    @Test public void disconnectDoesNotPublishOrLeavePlaintext() throws Exception {
        byte[] bytes = new byte[]{1, 2, 3};
        assertThrows(EOFException.class, () -> store.put(id(bytes), 1000, new ByteArrayInputStream(bytes)));
        assertEquals(0, root.list().length);
    }
    @Test public void wrongDigestCannotPublish() throws Exception {
        assertThrows(IOException.class, () -> store.put("0".repeat(64), 3, new ByteArrayInputStream(new byte[]{1, 2, 3})));
        assertEquals(0, root.list().length);
    }
    @Test public void retriesPreserveExistingObject() throws Exception {
        byte[] bytes = new byte[]{1, 2, 3};
        String id = id(bytes);
        store.put(id, 3, new ByteArrayInputStream(bytes));
        byte[] before = Files.readAllBytes(new File(root, id + ".encrypted").toPath());
        store.put(id, 3, new ByteArrayInputStream(bytes));
        assertArrayEquals(before, Files.readAllBytes(new File(root, id + ".encrypted").toPath()));
    }
    @Test public void corruptAndTruncatedCiphertextRejected() throws Exception {
        byte[] bytes = new byte[2000000];
        String id = id(bytes);
        store.put(id, bytes.length, new ByteArrayInputStream(bytes));
        File file = new File(root, id + ".encrypted");
        byte[] encrypted = Files.readAllBytes(file.toPath());
        encrypted[encrypted.length - 1] ^= 1;
        Files.write(file.toPath(), encrypted);
        assertThrows(Exception.class, () -> store.verify(id));
        Files.write(file.toPath(), Arrays.copyOf(encrypted, encrypted.length - 100));
        assertThrows(Exception.class, () -> store.verify(id));
    }
    @Test public void ciphertextCannotBeRenamedAsAnotherObject() throws Exception {
        byte[] bytes = new byte[]{7};
        store.put(id(bytes), 1, new ByteArrayInputStream(bytes));
        Files.move(new File(root, id(bytes) + ".encrypted").toPath(), new File(root, "0".repeat(64) + ".encrypted").toPath());
        assertThrows(Exception.class, () -> store.verify("0".repeat(64)));
    }
    @Test public void traversalAndOversizeRejected() throws Exception {
        assertThrows(IOException.class, () -> store.put("../../outside", 0, InputStream.nullInputStream()));
        assertThrows(IOException.class, () -> store.put("0".repeat(64), BlobStore.MAX_BYTES + 1, InputStream.nullInputStream()));
    }
    @Test public void restartRemovesOnlyIncompleteObjects() throws Exception {
        byte[] bytes = new byte[]{8};
        store.put(id(bytes), 1, new ByteArrayInputStream(bytes));
        Files.write(new File(root, "receive-interrupted.partial").toPath(), new byte[]{0});
        new BlobStore(root, cipher).verify(id(bytes));
        assertEquals(1, root.list().length);
    }
}
