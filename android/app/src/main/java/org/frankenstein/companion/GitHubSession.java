package org.frankenstein.companion;

import android.content.Context;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.json.JSONObject;

/** Crash journal is encrypted with the same device storage as portable objects.
 * Successful credentials live INSIDE the replicable vault, not a separate silo. */
final class GitHubSession {
    private static final Object LOCK = new Object();
    private final BlobStore store;
    private final NativeVault vault;
    private final AtomicFile journal;
    private final String origin;
    GitHubSession(Context context) throws Exception {
        store = LocalStorage.open(context); vault = new NativeVault(context);
        journal = new AtomicFile(new File(context.getNoBackupFilesDir(), "github-journal"));
        origin = Identity.fingerprint(Identity.certificate());
    }
    private JSONObject inspect(String generation) throws Exception { return vault.inspect(store, generation, null).getJSONObject("manifest"); }
    private String kit(String generation) throws Exception { return inspect(generation).getString("kit_id"); }
    JSONObject load() throws Exception {
        synchronized (LOCK) {
            replay();
            String generation = vault.current();
            if (generation.equals(NativeVault.EMPTY)) throw new GitHubClient.Failure("Create or receive a vault first");
            if (!inspect(generation).getJSONObject("files").has("credentials/github.json")) return null;
            byte[] bytes = android.util.Base64.decode(vault.inspect(store, generation, "credentials/github.json")
                .getJSONObject("selected").getString("base64"), android.util.Base64.NO_WRAP);
            try {
                JSONObject result = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
                if (result.getInt("schema") != 1 || !result.getString("origin_device").equals(origin))
                    throw new GitHubClient.Failure("Authorize GitHub on this device; replicated tokens must not be refreshed here");
                return result;
            } finally { Arrays.fill(bytes, (byte)0); }
        }
    }
    // Called only after an explicit owner sign-in. A new login can supersede an
    // interrupted rotation, but never writes tokens to another vault identity.
    JSONObject signIn(GitHubClient client, JSONObject tokens, String expectedKit) throws Exception {
        synchronized (LOCK) {
            JSONObject user = client.object("GET", "/user", tokens.getString("access_token"), null);
            String login = GitHubBackup.login(user);
            JSONObject credential = new JSONObject().put("schema", 1).put("origin_device", origin)
                .put("user_id", user.getLong("id")).put("login", login).put("tokens", tokens);
            save(credential, expectedKit);
            return credential;
        }
    }
    String currentKit() throws Exception { synchronized (LOCK) { return kit(vault.current()); } }
    JSONObject ready(GitHubClient client) throws Exception {
        synchronized (LOCK) {
            JSONObject credential = load();
            if (credential == null) throw new GitHubClient.Failure("Sign in to GitHub first");
            JSONObject tokens = credential.getJSONObject("tokens");
            if (tokens.optLong("expires_at", Long.MAX_VALUE) > System.currentTimeMillis() + 120000) return credential;
            if (!tokens.has("refresh_token") || tokens.optLong("refresh_expires_at", 0) <= System.currentTimeMillis())
                throw new GitHubClient.Failure("GitHub session expired; sign in again");
            String base = vault.current(), identity = kit(base);
            // An ambiguous timeout/crash cannot replay a single-use refresh token.
            writeJournal(new JSONObject().put("phase", "refresh_pending").put("base", base).put("kit_id", identity));
            JSONObject rotated = client.refresh(tokens);
            credential.put("tokens", rotated);
            // Persist the returned pair before doing native repack. On a repack
            // failure, the next owner-open replays this encrypted journal.
            writeJournal(new JSONObject().put("phase", "ready").put("base", base).put("kit_id", identity).put("credential", credential));
            replay();
            return credential;
        }
    }
    private void save(JSONObject credential, String identity) throws Exception {
        String base = vault.current();
        if (!kit(base).equals(identity)) throw new GitHubClient.Failure("Vault identity changed; sign in again");
        writeJournal(new JSONObject().put("phase", "ready").put("base", base).put("kit_id", identity).put("credential", credential));
        replay();
    }
    private void replay() throws Exception {
        JSONObject pending = readJournal();
        if (pending == null) return;
        if (!pending.getString("phase").equals("ready")) throw new GitHubClient.Failure("GitHub rotation was interrupted; sign in again");
        String selected = vault.current();
        if (!kit(selected).equals(pending.getString("kit_id"))) throw new GitHubClient.Failure("Pending GitHub credentials belong to another vault; sign in again");
        JSONObject credential = pending.getJSONObject("credential");
        if (!credential.getString("origin_device").equals(origin)) throw new GitHubClient.Failure("GitHub credential belongs to another device");
        if (!selected.equals(pending.getString("base"))) {
            // A crash after activation but before deleting the journal is safe.
            byte[] existing = android.util.Base64.decode(vault.inspect(store, selected, "credentials/github.json")
                .getJSONObject("selected").getString("base64"), android.util.Base64.NO_WRAP);
            try {
                if (!new String(existing, StandardCharsets.UTF_8).equals(credential.toString()))
                    throw new GitHubClient.Failure("Vault changed during GitHub save; sign in again");
            } finally { Arrays.fill(existing, (byte)0); }
        } else vault.amendGitHub(store, selected, credential);
        journal.delete();
    }
    private void writeJournal(JSONObject value) throws Exception {
        byte[] bytes = value.toString().getBytes(StandardCharsets.UTF_8);
        try {
            String id = GitHubBackup.sha(bytes);
            store.put(id, bytes.length, new ByteArrayInputStream(bytes));
            FileOutputStream output = null;
            try {
                output = journal.startWrite(); output.write(id.getBytes(StandardCharsets.US_ASCII)); journal.finishWrite(output);
            } catch (Exception error) { if (output != null) journal.failWrite(output); throw error; }
        } finally { Arrays.fill(bytes, (byte)0); }
    }
    private JSONObject readJournal() throws Exception {
        if (!journal.getBaseFile().exists() && !new File(journal.getBaseFile()+".bak").exists()) return null;
        String id;
        try (InputStream input = journal.openRead()) { id = new String(read(input, 64), StandardCharsets.US_ASCII); }
        store.verify(id);
        try (DataInputStream input = store.open(id)) {
            long length = input.readLong();
            if (length > 65536) throw new IOException("GitHub journal exceeds limit");
            byte[] bytes = read(input, 65536);
            try { return new JSONObject(new String(bytes, StandardCharsets.UTF_8)); }
            finally { Arrays.fill(bytes, (byte)0); }
        }
    }
    static byte[] read(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(); byte[] buffer = new byte[8192]; int count;
        while ((count=input.read(buffer)) != -1) {
            if (output.size()+count > limit) throw new IOException("GitHub data exceeds limit");
            output.write(buffer,0,count);
        }
        return output.toByteArray();
    }
}
