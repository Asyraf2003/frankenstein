package org.frankenstein.companion;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class GitHubBackupTest {
    static byte[] bytes(String text){return text.getBytes(StandardCharsets.UTF_8);}
    static Map<String,byte[]> fixture() throws Exception {
        Map<String,byte[]> files=new TreeMap<>();
        files.put("vault.age",bytes("synthetic encrypted archive"));
        files.put("recovery/identity.age",bytes("synthetic wrapped emergency identity"));
        files.put("recovery/recipient.txt",bytes("age1fixture\n"));
        JSONObject recovery=new JSONObject().put("schema",1).put("purpose","outer-kit-opening-v1").put("recipient","age1fixture")
            .put("identity_sha256",GitHubBackup.sha(files.get("recovery/identity.age"))).put("recipient_sha256",GitHubBackup.sha(files.get("recovery/recipient.txt")));
        files.put("recovery/manifest.json",bytes(recovery.toString()));
        files.put("backup.json",bytes(new JSONObject().put("schema",1).put("ciphertext_sha256",GitHubBackup.sha(files.get("vault.age")))
            .put("recovery_manifest_sha256",GitHubBackup.sha(files.get("recovery/manifest.json"))).put("context",new JSONObject()).toString()));
        return files;
    }
    static class Remote implements GitHubClient.Transport {
        final String parent="1".repeat(40), baseTree="2".repeat(40), commit="3".repeat(40);
        String head=parent, uploadedTree; boolean racing, privateRepo=true, wrongOwner, corruptDownload, published;
        final Map<String,byte[]> blobs=new HashMap<>(); final Map<String,JSONArray> trees=new HashMap<>();
        JSONObject user() throws Exception{return new JSONObject().put("login","fixture").put("id",42);}
        GitHubClient.Reply ok(Object value){return new GitHubClient.Reply(200,value.toString());}
        JSONObject entry(String path,String type,String sha) throws Exception{return new JSONObject().put("path",path).put("type",type).put("mode",type.equals("tree")?"040000":"100644").put("sha",sha);}
        String saveTree(JSONArray entries) throws Exception {
            String id=GitHubBackup.blobSha(bytes(entries.toString()));trees.put(id,entries);return id;
        }
        public GitHubClient.Reply call(String method,String url,String token,byte[] body,boolean form) throws Exception {
            assertEquals("synthetic_access",token); assertFalse(form);
            String path=url.substring("https://api.github.com".length()); JSONObject data=body==null?null:new JSONObject(new String(body,StandardCharsets.UTF_8));
            if(path.equals("/user"))return ok(user());
            if(path.equals("/repos/fixture/state"))return ok(new JSONObject().put("private",privateRepo).put("name","state").put("full_name","fixture/state")
                .put("owner",new JSONObject().put("id",wrongOwner?99:42)).put("permissions",new JSONObject().put("push",true)).put("default_branch","main"));
            if(path.endsWith("/git/ref/heads/main"))return ok(new JSONObject().put("object",new JSONObject().put("type","commit").put("sha",head)));
            if(path.endsWith("/git/commits/"+parent))return ok(new JSONObject().put("tree",new JSONObject().put("sha",baseTree)));
            if(path.contains("/contents/"))return new GitHubClient.Reply(404,"{}");
            if(path.endsWith("/git/blobs") && method.equals("POST")) {
                byte[] value=Base64.getDecoder().decode(data.getString("content"));String id=GitHubBackup.blobSha(value);blobs.put(id,value);return ok(new JSONObject().put("sha",id));
            }
            if(path.endsWith("/git/trees") && method.equals("POST")) {
                assertEquals(baseTree,data.getString("base_tree")); JSONArray entries=data.getJSONArray("tree"), recovery=new JSONArray(), backup=new JSONArray(); String digest="";
                for(int i=0;i<entries.length();i++) {
                    JSONObject entry=entries.getJSONObject(i);String[] parts=entry.getString("path").split("/");
                    assertEquals("frankenstein",parts[0]);assertEquals("backups",parts[1]);digest=parts[2];
                    if(parts.length==5)recovery.put(entry(parts[4],"blob",entry.getString("sha")));
                    else backup.put(entry(parts[3],"blob",entry.getString("sha")));
                }
                backup.put(entry("recovery","tree",saveTree(recovery)));
                String generations=saveTree(new JSONArray().put(entry(digest,"tree",saveTree(backup))));
                String frankenstein=saveTree(new JSONArray().put(entry("backups","tree",generations)));
                uploadedTree=saveTree(new JSONArray().put(entry("frankenstein","tree",frankenstein)));
                return ok(new JSONObject().put("sha",uploadedTree));
            }
            if(path.endsWith("/git/commits") && method.equals("POST")) {
                assertEquals(parent,data.getJSONArray("parents").getString(0));assertEquals(uploadedTree,data.getString("tree"));return ok(new JSONObject().put("sha",commit));
            }
            if(path.contains("/git/trees/") && method.equals("GET"))return ok(new JSONObject().put("tree",trees.get(path.substring(path.lastIndexOf('/')+1))));
            if(path.contains("/git/blobs/") && method.equals("GET")) {
                byte[] content=blobs.get(path.substring(path.lastIndexOf('/')+1));if(corruptDownload)content=bytes("corrupt");
                return ok(new JSONObject().put("encoding","base64").put("size",content.length).put("content",Base64.getEncoder().encodeToString(content)));
            }
            if(path.endsWith("/git/refs/heads/main") && method.equals("PATCH")) {
                assertFalse(data.getBoolean("force"));assertEquals(commit,data.getString("sha"));
                if(racing){head="4".repeat(40);return new GitHubClient.Reply(422,"{\"message\":\"secret remote details\"}");}
                published=true;head=commit;return ok(new JSONObject().put("object",new JSONObject().put("sha",commit)));
            }
            throw new AssertionError("Unexpected request "+method+" "+path);
        }
        GitHubBackup adapter() throws Exception {
            JSONObject credential=new JSONObject().put("user_id",42).put("tokens",new JSONObject().put("access_token","synthetic_access"));
            return new GitHubBackup(new GitHubClient(this,new GitHubClientTest.Time()),credential);
        }
    }
    @Test public void ciphertextPublishesAsOneCommitAndDownloadsInPcCompatibleLayout() throws Exception {
        Remote remote=new Remote();GitHubBackup adapter=remote.adapter();GitHubBackup.Selection selected=adapter.select("state","");
        Map<String,byte[]> files=fixture();String digest=adapter.publish(selected,files);assertTrue(remote.published);
        Map<String,byte[]> restored=adapter.download(new GitHubBackup.Selection(selected.repository,"main",remote.commit,remote.uploadedTree),digest);
        for(String name:GitHubBackup.FILES)assertArrayEquals(files.get(name),restored.get(name));
        assertEquals(5,remote.blobs.size());
    }
    @Test public void racingWriterAndStaleLeaseNeverForceOverwrite() throws Exception {
        Remote remote=new Remote();GitHubBackup adapter=remote.adapter();GitHubBackup.Selection selected=adapter.select("state","");remote.racing=true;
        assertThrows(GitHubClient.Failure.class,()->adapter.publish(selected,fixture()));assertFalse(remote.published);assertEquals("4".repeat(40),remote.head);
        int count=remote.blobs.size();assertThrows(GitHubClient.Failure.class,()->adapter.publish(selected,fixture()));assertEquals(count,remote.blobs.size());
    }
    @Test public void publicOrOtherOwnersRepositoryIsRejectedBeforeWriting() throws Exception {
        Remote remote=new Remote();GitHubBackup adapter=remote.adapter();remote.privateRepo=false;
        assertThrows(GitHubClient.Failure.class,()->adapter.select("state",""));remote.privateRepo=true;remote.wrongOwner=true;
        assertThrows(GitHubClient.Failure.class,()->adapter.select("state",""));assertTrue(remote.blobs.isEmpty());
    }
    @Test public void corruptedReadBackPreventsPublication() throws Exception {
        Remote remote=new Remote();GitHubBackup adapter=remote.adapter();GitHubBackup.Selection selected=adapter.select("state","");remote.corruptDownload=true;
        assertThrows(GitHubClient.Failure.class,()->adapter.publish(selected,fixture()));assertFalse(remote.published);assertEquals(remote.parent,remote.head);
    }
    @Test public void extraPlaintextAndOversizedBackupAreRejected() throws Exception {
        Map<String,byte[]> extra=fixture();extra.put("identity.txt",bytes("private"));assertThrows(GitHubClient.Failure.class,()->GitHubBackup.validate(extra));
        Map<String,byte[]> oversized=fixture();oversized.put("vault.age",new byte[GitHubBackup.MAX_BACKUP]);assertThrows(GitHubClient.Failure.class,()->GitHubBackup.validate(oversized));
    }
}
