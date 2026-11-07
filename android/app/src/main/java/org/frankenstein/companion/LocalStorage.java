package org.frankenstein.companion;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.google.crypto.tink.*;
import com.google.crypto.tink.integration.android.AndroidKeystoreKmsClient;
import com.google.crypto.tink.streamingaead.StreamingAeadConfig;
import java.io.*;
import java.nio.file.Files;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;

final class LocalStorage {
    private static final java.util.Map<String, BlobStore> stores = new java.util.HashMap<>();
    static synchronized BlobStore open(Context context) throws Exception {
        String location = context.getNoBackupFilesDir().getCanonicalPath();
        BlobStore existing = stores.get(location);
        if (existing != null) return existing;
        StreamingAeadConfig.register();
        String alias = "frankenstein-storage-v1";
        File root = context.getNoBackupFilesDir();
        File keyset = new File(root, "storage-keyset.encrypted");
        KeyStore keys = KeyStore.getInstance("AndroidKeyStore");
        keys.load(null);
        if (!keys.containsAlias(alias)) {
            if (keyset.exists()) throw new IOException("Storage key lost; restore from another device or backup");
            KeyGenerator generator = KeyGenerator.getInstance("AES", "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setUnlockedDeviceRequired(true).build());
            generator.generateKey();
        }
        Aead wrapping = new AndroidKeystoreKmsClient().getAead("android-keystore://" + alias);
        KeysetHandle handle;
        if (keyset.exists()) {
            handle = KeysetHandle.read(JsonKeysetReader.withFile(keyset), wrapping);
        } else {
            handle = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM_HKDF_1MB"));
            File temporary = File.createTempFile("keyset-", ".partial", root);
            try {
                handle.write(JsonKeysetWriter.withFile(temporary), wrapping);
                try (FileOutputStream out = new FileOutputStream(temporary, true)) { out.getFD().sync(); }
                Files.move(temporary.toPath(), keyset.toPath());
            } finally { Files.deleteIfExists(temporary.toPath()); }
        }
        BlobStore store = new BlobStore(new File(root, "objects"), handle.getPrimitive(StreamingAead.class));
        stores.put(location, store);
        return store;
    }
}
