package org.frankenstein.companion;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;

final class Identity {
    static final String ALIAS = "frankenstein-device-v1";
    static synchronized KeyStore keys() throws Exception {
        KeyStore keys = KeyStore.getInstance("AndroidKeyStore");
        keys.load(null);
        if (!keys.containsAlias(ALIAS)) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384, KeyProperties.DIGEST_SHA512)
                .setCertificateSubject(new X500Principal("CN=Frankenstein device"))
                .setCertificateSerialNumber(new BigInteger(128, new SecureRandom()))
                .setCertificateNotBefore(new Date(System.currentTimeMillis() - 86400000L))
                .setCertificateNotAfter(new Date(System.currentTimeMillis() + 10L * 365 * 86400000L)).build());
            generator.generateKeyPair();
        }
        return keys;
    }
    static X509Certificate certificate() throws Exception { return (X509Certificate) keys().getCertificate(ALIAS); }
    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder();
        for (byte b : bytes) out.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return out.toString();
    }
    static String fingerprint(X509Certificate cert) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
    }
    static SSLContext context(X509Certificate peer) throws Exception {
        KeyStore keys = keys();
        // Expose only this application's device identity to JSSE.
        X509ExtendedKeyManager km = new X509ExtendedKeyManager() {
            public String[] getClientAliases(String type, Principal[] issuers) { return new String[]{ALIAS}; }
            public String chooseClientAlias(String[] types, Principal[] issuers, java.net.Socket s) { return ALIAS; }
            public String[] getServerAliases(String type, Principal[] issuers) { return new String[]{ALIAS}; }
            public String chooseServerAlias(String type, Principal[] issuers, java.net.Socket s) { return type.equals("EC") ? ALIAS : null; }
            public X509Certificate[] getCertificateChain(String alias) {
                try { return new X509Certificate[]{(X509Certificate) keys.getCertificate(ALIAS)}; }
                catch (Exception e) { throw new IllegalStateException(e); }
            }
            public PrivateKey getPrivateKey(String alias) {
                try { return (PrivateKey) keys.getKey(ALIAS, null); }
                catch (Exception e) { throw new IllegalStateException(e); }
            }
        };
        // The only trust anchor is the exact certificate approved by the owner.
        X509TrustManager trust = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{peer}; }
            public void checkClientTrusted(X509Certificate[] chain, String auth) throws java.security.cert.CertificateException {
                if (chain.length != 1 || !chain[0].equals(peer)) throw new java.security.cert.CertificateException("Unapproved device");
                peer.checkValidity();
            }
            public void checkServerTrusted(X509Certificate[] chain, String auth) throws java.security.cert.CertificateException { checkClientTrusted(chain, auth); }
        };
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(new KeyManager[]{km}, new TrustManager[]{trust}, null);
        return context;
    }
}
