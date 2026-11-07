package org.frankenstein.companion;

import android.content.Context;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** Physical Keystore/native integration using isolated synthetic credentials. */
final class GitHubStorageChecks {
    static void run(Context context, BlobStore store, NativeVault vault) throws Exception {
        run(context, store, vault, "github-amended-fixture.zip");
    }
    static void run(Context context, BlobStore store, NativeVault vault, String filename) throws Exception {
        GitHubSession session=new GitHubSession(context);
        String identity=session.currentKit();
        GitHubClient client=new GitHubClient((method,url,token,body,form)->{
            if(url.equals("https://api.github.com/user"))return new GitHubClient.Reply(200,"{\"login\":\"fixture\",\"id\":42}");
            if(url.equals("https://github.com/login/oauth/access_token"))return new GitHubClient.Reply(200,
                "{\"access_token\":\"synthetic_rotated\",\"refresh_token\":\"synthetic_rotated_refresh\",\"token_type\":\"bearer\",\"scope\":\"repo\",\"expires_in\":28800,\"refresh_token_expires_in\":15552000}");
            throw new AssertionError("Unexpected request");
        },new GitHubClient.Clock(){public long millis(){return 0;}public void sleep(long ignored){}});
        JSONObject tokens=new JSONObject().put("access_token","synthetic_expired").put("refresh_token","synthetic_previous_refresh")
            .put("expires_at",1).put("refresh_expires_at",System.currentTimeMillis()+86400000).put("scope","repo");
        session.signIn(client,tokens,identity);
        JSONObject ready=session.ready(client);
        if(!ready.getJSONObject("tokens").getString("access_token").equals("synthetic_rotated"))throw new AssertionError("Rotation missing");
        if(!new GitHubSession(context).load().getJSONObject("tokens").getString("refresh_token").equals("synthetic_rotated_refresh"))throw new AssertionError("Rotated pair not durable");
        if(!session.currentKit().equals(identity))throw new AssertionError("Vault identity changed");
        // Simulate a crash after durable receipt of credentials, before repack.
        JSONObject next=new JSONObject(ready.toString()); next.getJSONObject("tokens").put("access_token","synthetic_replayed");
        journal(context,store,new JSONObject().put("phase","ready").put("base",vault.current()).put("kit_id",identity).put("credential",next));
        if(!new GitHubSession(context).load().getJSONObject("tokens").getString("access_token").equals("synthetic_replayed"))throw new AssertionError("Journal did not replay");
        // Crash after remote rotation, before receipt: do not replay old refresh.
        journal(context,store,new JSONObject().put("phase","refresh_pending").put("base",vault.current()).put("kit_id",identity));
        boolean refused=false;try{new GitHubSession(context).ready(client);}catch(GitHubClient.Failure expected){refused=true;}
        if(!refused)throw new AssertionError("Ambiguous refresh was replayed");
        session.signIn(client,next.getJSONObject("tokens"),identity);
        JSONObject foreign=new JSONObject(session.load().toString()).put("origin_device","0".repeat(64));
        vault.amendGitHub(store,vault.current(),foreign);
        refused=false;try{session.ready(client);}catch(GitHubClient.Failure expected){refused=true;}
        if(!refused)throw new AssertionError("Replicated rotating token used on another device");
        session.signIn(client,next.getJSONObject("tokens"),identity);
        java.util.Map<String,byte[]> files=GitHubBackup.capture(store,vault,vault.current());
        for(byte[] bytes:files.values()) {
            String publicBytes=new String(bytes,StandardCharsets.ISO_8859_1);
            if(publicBytes.contains("synthetic_replayed") || publicBytes.contains("AGE-SECRET-KEY-"))throw new AssertionError("Plaintext escaped backup");
        }
        File exported=new File(context.getExternalFilesDir(null),filename);
        try(OutputStream output=new FileOutputStream(exported)){GitHubBackup.recoveryZip(files,output);}
    }
    private static void journal(Context context,BlobStore store,JSONObject value) throws Exception {
        byte[] bytes=value.toString().getBytes(StandardCharsets.UTF_8);String id=GitHubBackup.sha(bytes);
        store.put(id,bytes.length,new ByteArrayInputStream(bytes));
        AtomicFile journal=new AtomicFile(new File(context.getNoBackupFilesDir(),"github-journal"));
        FileOutputStream output=journal.startWrite();output.write(id.getBytes(StandardCharsets.US_ASCII));journal.finishWrite(output);
        java.util.Arrays.fill(bytes,(byte)0);
    }
}
