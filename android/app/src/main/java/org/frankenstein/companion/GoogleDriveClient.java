package org.frankenstein.companion;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;

/** Browser OAuth with S256 PKCE. No client secret or user password in the APK. */
final class GoogleDriveClient {
    static final String DRIVE_SCOPE = "https://www.googleapis.com/auth/drive";
    interface Transport { JSONObject call(String endpoint, String token, byte[] body) throws Exception; }
    static final class Failure extends IOException { Failure(String message) { super(message); } }
    static final class Pending {
        final String clientId, redirect, verifier, state, email, kit, generation;
        final long started;
        private boolean consumed;
        Pending(String clientId, String verifier, String state, String email, String kit, String generation, long started) {
            this.clientId=clientId;
            this.redirect="com.googleusercontent.apps."+clientId.replace(".apps.googleusercontent.com","")+":/oauth2redirect";
            this.verifier=verifier; this.state=state; this.email=email; this.kit=kit; this.generation=generation; this.started=started;
        }
    }
    static Pending begin(String email, String kit, String generation, long now) throws Exception {
        return begin(BuildConfig.GOOGLE_DRIVE_CLIENT_ID,email,kit,generation,now);
    }
    static Pending begin(String clientId, String email, String kit, String generation, long now) throws Exception {
        if(!clientId.matches("[0-9]+-[a-z0-9]+\\.apps\\.googleusercontent\\.com"))
            throw new Failure("Google Drive is not configured for this development build.");
        if (!email.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+") || email.length()>254)
            throw new Failure("Your vault has no valid Google email. Complete your phone setup first.");
        SecureRandom random=new SecureRandom(); byte[] verifier=new byte[32], state=new byte[32];
        random.nextBytes(verifier); random.nextBytes(state);
        return new Pending(clientId,url64(verifier),url64(state),email,kit,generation,now);
    }
    static String url64(byte[] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    static String challenge(String verifier) throws Exception {
        return url64(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
    }
    static String form(String... pairs) throws Exception {
        StringBuilder out=new StringBuilder();
        for(int i=0;i<pairs.length;i+=2) {
            if(out.length()>0) out.append('&');
            out.append(URLEncoder.encode(pairs[i],"UTF-8")).append('=').append(URLEncoder.encode(pairs[i+1],"UTF-8"));
        }
        return out.toString();
    }
    static String authorization(Pending pending) throws Exception {
        return "https://accounts.google.com/o/oauth2/v2/auth?"+form("client_id",pending.clientId,"redirect_uri",pending.redirect,
            "response_type","code","scope","openid email "+DRIVE_SCOPE,"access_type","offline","prompt","consent",
            "login_hint",pending.email,"state",pending.state,"code_challenge",challenge(pending.verifier),"code_challenge_method","S256");
    }
    static synchronized String callback(Pending pending,String address,long now) throws Exception {
        if(pending==null || pending.consumed || now<pending.started || now-pending.started>10*60*1000L)
            throw new Failure("Google login expired. Connect again.");
        URI uri;
        try { uri=new URI(address); } catch(Exception e) { throw new Failure("Invalid Google callback"); }
        if(address.length()>8192 || uri.getRawFragment()!=null || uri.getRawQuery()==null ||
            !address.substring(0,address.indexOf('?')).equals(pending.redirect)) throw new Failure("Invalid Google callback");
        Map<String,String> query=new HashMap<>();
        for(String part:uri.getRawQuery().split("&")) {
            String[] pair=part.split("=",2);
            String key=URLDecoder.decode(pair[0],"UTF-8");
            if(pair.length!=2 || query.put(key,URLDecoder.decode(pair[1],"UTF-8"))!=null)
                throw new Failure("Invalid Google callback");
        }
        if(!MessageDigest.isEqual(pending.state.getBytes(StandardCharsets.UTF_8),
            query.getOrDefault("state","").getBytes(StandardCharsets.UTF_8))) throw new Failure("Google login does not match this request");
        pending.consumed=true;
        if(query.containsKey("error")) throw new Failure("Google authorization was not completed. Connect again when ready.");
        String code=query.get("code");
        if(code==null || code.isEmpty() || code.length()>4096 || code.chars().anyMatch(c->c<33 || c>126))
            throw new Failure("Invalid Google authorization code");
        return code;
    }
    private final Transport transport;
    GoogleDriveClient() { this(new Https()); }
    GoogleDriveClient(Transport transport) { this.transport=transport; }
    JSONObject exchange(Pending pending,String code,long now) throws Exception {
        byte[] body=form("client_id",pending.clientId,"redirect_uri",pending.redirect,"grant_type","authorization_code",
            "code",code,"code_verifier",pending.verifier).getBytes(StandardCharsets.UTF_8);
        JSONObject tokens;
        try { tokens=transport.call("https://oauth2.googleapis.com/token",null,body); }
        finally { Arrays.fill(body,(byte)0); }
        String access=tokens.optString("access_token"), refresh=tokens.optString("refresh_token");
        if(!safeToken(access) || !safeToken(refresh) || !tokens.optString("token_type").equalsIgnoreCase("Bearer"))
            throw new Failure("Google did not provide offline access. Connect again and approve Drive access.");
        Set<String> scopes=new HashSet<>(Arrays.asList(tokens.optString("scope").split(" +")));
        Set<String> allowed=new HashSet<>(Arrays.asList(DRIVE_SCOPE,"openid","email","https://www.googleapis.com/auth/userinfo.email"));
        if(!scopes.contains(DRIVE_SCOPE) || !allowed.containsAll(scopes)) throw new Failure("Google Drive permission mismatch");
        long seconds=tokens.optLong("expires_in",0);
        if(seconds<1 || seconds>86400) throw new Failure("Invalid Google credential expiry");
        JSONObject user=transport.call("https://openidconnect.googleapis.com/v1/userinfo",access,null);
        if(!user.optBoolean("email_verified") || !pending.email.equalsIgnoreCase(user.optString("email")))
            throw new Failure("The Google account differs from your phone setup. Connect with "+pending.email+".");
        return new JSONObject().put("schema",1).put("account",pending.email).put("client_id",pending.clientId)
            .put("access_token",access).put("refresh_token",refresh).put("token_type","Bearer")
            .put("scope",tokens.getString("scope")).put("expiry",Instant.ofEpochMilli(now+seconds*1000).toString());
    }
    private static boolean safeToken(String token) {
        return !token.isEmpty() && token.length()<=8192 && token.chars().allMatch(c->c>=33 && c<=126);
    }
    private static final class Https implements Transport {
        public JSONObject call(String endpoint,String token,byte[] body) throws Exception {
            if(!(endpoint.equals("https://oauth2.googleapis.com/token") && token==null && body!=null) &&
               !(endpoint.equals("https://openidconnect.googleapis.com/v1/userinfo") && token!=null && body==null))
                throw new Failure("Google credential destination rejected");
            HttpsURLConnection connection=(HttpsURLConnection)new URL(endpoint).openConnection();
            Timer watchdog=new Timer(true);
            watchdog.schedule(new TimerTask(){public void run(){connection.disconnect();}},45000);
            try {
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(15000); connection.setReadTimeout(15000);
                connection.setRequestProperty("Accept","application/json");
                if(token!=null) connection.setRequestProperty("Authorization","Bearer "+token);
                if(body!=null) {
                    connection.setRequestMethod("POST"); connection.setDoOutput(true);
                    connection.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
                    connection.setFixedLengthStreamingMode(body.length);
                    try(OutputStream out=connection.getOutputStream()){out.write(body);}
                }
                int status=connection.getResponseCode();
                if(status!=200) throw new Failure("Google authorization failed (HTTP "+status+"). Connect again.");
                try(InputStream input=connection.getInputStream()) {
                    byte[] bytes=GitHubSession.read(input,65536);
                    try { return new JSONObject(new String(bytes,StandardCharsets.UTF_8)); }
                    finally { Arrays.fill(bytes,(byte)0); }
                }
            } finally { watchdog.cancel(); connection.disconnect(); }
        }
    }
}
