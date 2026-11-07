package org.frankenstein.companion;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;
import org.json.*;

/** Small-vault Git adapter, using the PC backup format and non-force ref writes. */
final class GitHubBackup {
    static final int MAX_BACKUP = 8 * 1024 * 1024;
    static final Set<String> FILES = new HashSet<>(Arrays.asList("vault.age", "backup.json",
        "recovery/identity.age", "recovery/recipient.txt", "recovery/manifest.json"));
    private final GitHubClient client;
    private final String token;
    private final JSONObject user;
    GitHubBackup(GitHubClient client, JSONObject credential) throws Exception {
        this.client = client; token = credential.getJSONObject("tokens").getString("access_token");
        user = client.object("GET", "/user", token, null);
        if (user.getLong("id") != credential.getLong("user_id")) throw new GitHubClient.Failure("GitHub account changed; sign in again");
        login(user);
    }
    static String login(JSONObject user) throws Exception {
        String login = user.getString("login");
        if (!login.matches("[A-Za-z0-9][A-Za-z0-9-]{0,38}") || user.getLong("id") <= 0) throw new GitHubClient.Failure("Invalid GitHub account");
        return login;
    }
    static String name(String value) throws IOException {
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,99}") || value.contains("..")) throw new GitHubClient.Failure("Invalid repository name");
        return value;
    }
    static String branch(String value) throws IOException {
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9_./-]{0,199}") || value.contains("..") || value.contains("//") ||
            value.endsWith("/") || value.endsWith(".") || value.endsWith(".lock") || value.contains("/.") || value.contains(".lock/"))
            throw new GitHubClient.Failure("Invalid branch name");
        return value;
    }
    private JSONObject owned(JSONObject repo) throws Exception {
        if (!repo.getBoolean("private") || repo.optBoolean("archived") || repo.optBoolean("disabled") ||
            repo.getJSONObject("owner").getLong("id") != user.getLong("id") || !repo.getJSONObject("permissions").optBoolean("push"))
            throw new GitHubClient.Failure("Select your own writable private repository");
        name(repo.getString("name"));
        return repo;
    }
    List<String> repositories() throws Exception {
        List<String> result = new ArrayList<>();
        for (int page=1; page<=20; page++) {
            GitHubClient.Reply reply = client.api("GET", "/user/repos?affiliation=owner&visibility=private&per_page=100&page="+page, token, null);
            if (reply.status != 200) throw new GitHubClient.Failure("Could not list private repositories");
            JSONArray repos = new JSONArray(reply.body);
            for (int i=0; i<repos.length(); i++) {
                try { result.add(owned(repos.getJSONObject(i)).getString("name")); }
                catch (GitHubClient.Failure ignored) { /* Non-writable repos are not choices. */ }
            }
            if (repos.length() < 100) return result;
        }
        throw new GitHubClient.Failure("Too many repositories to list; select by name");
    }
    JSONObject create(String repository) throws Exception {
        name(repository);
        return owned(client.object("POST", "/user/repos", token, new JSONObject().put("name", repository)
            .put("private", true).put("auto_init", true).put("description", "Encrypted Frankenstein state")));
    }
    static final class Selection {
        final String repository, branch, parent, tree;
        Selection(String repository, String branch, String parent, String tree) {
            this.repository=repository; this.branch=branch; this.parent=parent; this.tree=tree;
        }
    }
    Selection select(String repository, String selectedBranch) throws Exception {
        String full = login(user)+"/"+name(repository);
        JSONObject repo = owned(client.object("GET", "/repos/"+full, token, null));
        String ref = branch(selectedBranch.isEmpty() ? repo.getString("default_branch") : selectedBranch);
        String head = head(full,ref);
        JSONObject commit = client.object("GET", "/repos/"+full+"/git/commits/"+head,token,null);
        return new Selection(full,ref,head,gitSha(commit.getJSONObject("tree").getString("sha")));
    }
    private String head(String full, String branch) throws Exception {
        JSONObject object = client.object("GET", "/repos/"+full+"/git/ref/heads/"+branch, token,null).getJSONObject("object");
        if (!object.getString("type").equals("commit")) throw new GitHubClient.Failure("Selected branch is not a commit");
        return gitSha(object.getString("sha"));
    }
    private static String gitSha(String value) throws IOException {
        if (!value.matches("[0-9a-f]{40}")) throw new GitHubClient.Failure("Invalid GitHub object");
        return value;
    }
    private void lease(Selection selected) throws Exception {
        String repository = selected.repository.substring(selected.repository.indexOf('/')+1);
        JSONObject repo = owned(client.object("GET", "/repos/"+login(user)+"/"+name(repository), token, null));
        if (!repo.getString("full_name").equalsIgnoreCase(selected.repository) || !head(selected.repository,selected.branch).equals(selected.parent))
            throw new GitHubClient.Failure("GitHub conflict; reload the selected branch before trying again");
    }
    String publish(Selection selected, Map<String,byte[]> files) throws Exception {
        String digest = validate(files);
        lease(selected);
        String root = "/repos/"+selected.repository;
        // Immutable backup directories never replace a prior recovery generation.
        GitHubClient.Reply exists = client.api("GET",root+"/contents/frankenstein/backups/"+digest+"?ref="+selected.parent,token,null);
        if (exists.status != 404) throw new GitHubClient.Failure(exists.status == 200 ? "This backup already exists; download it to verify" : "Could not inspect backup destination");
        JSONArray entries = new JSONArray();
        for (String path : new TreeSet<>(FILES)) {
            client.check();
            byte[] bytes = files.get(path);
            JSONObject blob = client.object("POST",root+"/git/blobs",token,new JSONObject().put("encoding","base64")
                .put("content",Base64.getEncoder().encodeToString(bytes)));
            String blobId = gitSha(blob.getString("sha"));
            if (!blobId.equals(blobSha(bytes))) throw new GitHubClient.Failure("Uploaded ciphertext object mismatch");
            entries.put(new JSONObject().put("path","frankenstein/backups/"+digest+"/"+path)
                .put("mode","100644").put("type","blob").put("sha",blobId));
        }
        String tree = gitSha(client.object("POST",root+"/git/trees",token,new JSONObject()
            .put("base_tree",selected.tree).put("tree",entries)).getString("sha"));
        String commit = gitSha(client.object("POST",root+"/git/commits",token,new JSONObject()
            .put("message","Back up encrypted Frankenstein state").put("tree",tree)
            .put("parents",new JSONArray().put(selected.parent))).getString("sha"));
        // Download and compare all ciphertext BEFORE making this commit visible.
        Map<String,byte[]> downloaded = downloadTree(selected.repository,tree,digest);
        for (String path : FILES) if (!Arrays.equals(files.get(path),downloaded.get(path))) throw new GitHubClient.Failure("GitHub read-back mismatch");
        lease(selected);
        // Sibling commits fail non-fast-forward even if another writer races the
        // preceding lease check. Never retry or silently rebase on a new parent.
        JSONObject published = client.object("PATCH",root+"/git/refs/heads/"+selected.branch,token,
            new JSONObject().put("sha",commit).put("force",false));
        if (!published.getJSONObject("object").getString("sha").equals(commit)) throw new GitHubClient.Failure("GitHub publication could not be confirmed");
        return digest;
    }
    Map<String,byte[]> download(Selection selected, String digest) throws Exception {
        return downloadTree(selected.repository,selected.tree,digest);
    }
    private JSONArray tree(String repository, String sha) throws Exception {
        JSONObject response = client.object("GET","/repos/"+repository+"/git/trees/"+gitSha(sha),token,null);
        if (response.optBoolean("truncated")) throw new GitHubClient.Failure("GitHub tree exceeds supported limit");
        return response.getJSONArray("tree");
    }
    private String directory(String repository, String sha, String name) throws Exception {
        JSONArray entries = tree(repository,sha);
        for (int i=0;i<entries.length();i++) {
            JSONObject entry = entries.getJSONObject(i);
            if (entry.getString("path").equals(name)) {
                if (!entry.getString("type").equals("tree") || !entry.getString("mode").equals("040000")) break;
                return gitSha(entry.getString("sha"));
            }
        }
        throw new GitHubClient.Failure("Selected encrypted backup is missing");
    }
    private Map<String,byte[]> downloadTree(String repository, String root, String digest) throws Exception {
        if (!digest.matches("[0-9a-f]{64}")) throw new GitHubClient.Failure("Enter the 64-character backup digest");
        String selected = root;
        for (String part : new String[]{"frankenstein","backups",digest}) selected = directory(repository,selected,part);
        Map<String,String> objects = new TreeMap<>();
        collect(repository,selected,"",objects);
        if (!objects.keySet().equals(FILES)) throw new GitHubClient.Failure("Unexpected backup files");
        Map<String,byte[]> result = new TreeMap<>(); int total=0;
        for (Map.Entry<String,String> entry : objects.entrySet()) {
            JSONObject blob = client.object("GET","/repos/"+repository+"/git/blobs/"+entry.getValue(),token,null);
            long size = blob.getLong("size");
            if (size < 0 || size > MAX_BACKUP-total || !blob.getString("encoding").equals("base64")) throw new GitHubClient.Failure("Cloud backup exceeds 8 MiB limit");
            byte[] bytes = Base64.getDecoder().decode(blob.getString("content").replace("\n", "").replace("\r", ""));
            if (bytes.length != size || !blobSha(bytes).equals(entry.getValue())) throw new GitHubClient.Failure("Downloaded ciphertext object mismatch");
            total += bytes.length; result.put(entry.getKey(),bytes);
        }
        if (!validate(result).equals(digest)) throw new GitHubClient.Failure("Backup digest mismatch");
        return result;
    }
    private void collect(String repository, String selected, String prefix, Map<String,String> objects) throws Exception {
        JSONArray entries = tree(repository,selected);
        if (entries.length() > 5) throw new GitHubClient.Failure("Unexpected backup entries");
        for (int i=0;i<entries.length();i++) {
            JSONObject entry = entries.getJSONObject(i); String path=prefix+entry.getString("path");
            if (path.equals("recovery") && entry.getString("type").equals("tree") && entry.getString("mode").equals("040000"))
                collect(repository,gitSha(entry.getString("sha")),"recovery/",objects);
            else {
                if (!FILES.contains(path) || !entry.getString("type").equals("blob") || !entry.getString("mode").equals("100644") || objects.containsKey(path))
                    throw new GitHubClient.Failure("Unexpected backup entry");
                objects.put(path,gitSha(entry.getString("sha")));
            }
        }
    }
    static Map<String,byte[]> capture(BlobStore store, NativeVault vault, String id) throws Exception {
        try (DataInputStream input=store.open(id)) {
            if (input.readLong() > MAX_BACKUP) throw new GitHubClient.Failure("Cloud backup supports vaults up to 8 MiB; export larger vaults by USB");
        }
        // Reuse the explicit ciphertext-only export allowlist.
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();
        BackupExport.write(store,vault,id,bytes);
        Map<String,byte[]> files=new TreeMap<>(); JSONObject selection=null,context=null; int total=0;
        try (ZipInputStream zip=new ZipInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            ZipEntry entry;
            while ((entry=zip.getNextEntry())!=null) {
                byte[] data=GitHubSession.read(zip,MAX_BACKUP-total); total+=data.length;
                if (entry.getName().equals("context.json")) context=json(data);
                else if (entry.getName().equals("selection.json")) selection=json(data);
                else if (FILES.contains(entry.getName())) files.put(entry.getName(),data);
                else throw new GitHubClient.Failure("Unexpected ciphertext export entry");
            }
        }
        if (selection==null || context==null) throw new GitHubClient.Failure("Incomplete ciphertext export");
        files.put("backup.json",new JSONObject().put("schema",1).put("ciphertext_sha256",selection.getString("archive_sha256"))
            .put("context",context).put("recovery_manifest_sha256",selection.getString("recovery_manifest_sha256")).toString().getBytes(StandardCharsets.UTF_8));
        validate(files); return files;
    }
    static String validate(Map<String,byte[]> files) throws Exception {
        if (!files.keySet().equals(FILES)) throw new GitHubClient.Failure("Incomplete encrypted backup");
        long total=0; for (byte[] bytes:files.values()) total+=bytes.length;
        if (total > MAX_BACKUP) throw new GitHubClient.Failure("Cloud backup exceeds 8 MiB limit");
        for (String path:FILES) if (!path.equals("vault.age") && files.get(path).length>65536) throw new GitHubClient.Failure("Backup metadata exceeds limit");
        JSONObject metadata=json(files.get("backup.json")), recovery=json(files.get("recovery/manifest.json"));
        String digest=sha(files.get("vault.age"));
        if (metadata.getInt("schema")!=1 || !digest.equals(metadata.getString("ciphertext_sha256")) ||
            !sha(files.get("recovery/manifest.json")).equals(metadata.getString("recovery_manifest_sha256")) ||
            recovery.getInt("schema")!=1 || !recovery.getString("purpose").equals("outer-kit-opening-v1") ||
            !sha(files.get("recovery/identity.age")).equals(recovery.getString("identity_sha256")) ||
            !sha(files.get("recovery/recipient.txt")).equals(recovery.getString("recipient_sha256")) ||
            !new String(files.get("recovery/recipient.txt"),StandardCharsets.UTF_8).equals(recovery.getString("recipient")+"\n"))
            throw new GitHubClient.Failure("Encrypted backup integrity mismatch");
        metadata.getJSONObject("context");
        return digest;
    }
    static void recoveryZip(Map<String,byte[]> files, OutputStream target) throws Exception {
        String digest=validate(files); JSONObject metadata=json(files.get("backup.json"));
        try (ZipOutputStream zip=new ZipOutputStream(target)) {
            for (String path: new TreeSet<>(FILES)) if (!path.equals("backup.json")) zipEntry(zip,path,files.get(path));
            zipEntry(zip,"context.json",metadata.getJSONObject("context").toString().getBytes(StandardCharsets.UTF_8));
            zipEntry(zip,"selection.json",new JSONObject().put("schema",1).put("archive_sha256",digest)
                .put("recovery_manifest_sha256",metadata.getString("recovery_manifest_sha256")).toString().getBytes(StandardCharsets.UTF_8));
        }
    }
    private static void zipEntry(ZipOutputStream zip,String path,byte[] bytes) throws IOException { zip.putNextEntry(new ZipEntry(path)); zip.write(bytes); zip.closeEntry(); }
    private static JSONObject json(byte[] bytes) throws Exception { return new JSONObject(new String(bytes,StandardCharsets.UTF_8)); }
    static String sha(byte[] bytes) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    static String blobSha(byte[] bytes) throws Exception {
        MessageDigest hash=MessageDigest.getInstance("SHA-1");
        hash.update(("blob "+bytes.length+"\0").getBytes(StandardCharsets.US_ASCII)); return hex(hash.digest(bytes));
    }
    private static String hex(byte[] bytes) { StringBuilder out=new StringBuilder(); for (byte b:bytes) out.append(String.format(java.util.Locale.ROOT,"%02x",b&255)); return out.toString(); }
}
