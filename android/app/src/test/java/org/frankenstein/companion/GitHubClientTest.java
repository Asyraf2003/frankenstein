package org.frankenstein.companion;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;
import java.util.*;
import java.nio.charset.StandardCharsets;

public class GitHubClientTest {
    static final class Time implements GitHubClient.Clock {
        long now; Runnable onSleep;
        public long millis(){return now;}
        public void sleep(long millis){now+=millis;if(onSleep!=null)onSleep.run();}
    }
    static JSONObject token() throws Exception {return new JSONObject().put("access_token","synthetic_access")
        .put("token_type","bearer").put("scope","repo").put("expires_in",28800)
        .put("refresh_token","synthetic_refresh").put("refresh_token_expires_in",15552000);}
    static GitHubClient.Reply reply(JSONObject json){return new GitHubClient.Reply(200,json.toString());}
    @Test public void deviceFlowRespectsPendingSlowDownAndMinimumInterval() throws Exception {
        Time time=new Time(); List<Long> polls=new ArrayList<>(); List<String> forms=new ArrayList<>();
        GitHubClient client=new GitHubClient((method,url,secret,body,form)->{
            assertEquals("POST",method);assertNull(secret);assertTrue(form);
            forms.add(new String(body,StandardCharsets.UTF_8));
            if(url.endsWith("/device/code"))return reply(new JSONObject().put("device_code","synthetic_code").put("user_code","ABCD-EFGH")
                .put("verification_uri","https://github.com/login/device").put("interval",5).put("expires_in",900));
            polls.add(time.now);
            if(polls.size()==1)return reply(new JSONObject().put("error","authorization_pending"));
            if(polls.size()==2)return reply(new JSONObject().put("error","slow_down"));
            return reply(token());
        },time);
        assertEquals("synthetic_access",client.poll(client.begin()).getString("access_token"));
        assertEquals(Arrays.asList(5000L,10000L,20000L),polls);
        assertTrue(forms.get(0).contains("scope=repo"));
        for(String form:forms)assertFalse(form.contains("client_secret"));
    }
    @Test public void expiryDoesNotMakeLatePollAndCancellationStopsWaiting() throws Exception {
        Time time=new Time(); int[] calls={0};
        GitHubClient client=new GitHubClient((m,u,t,b,f)->{calls[0]++;return reply(token());},time);
        assertThrows(GitHubClient.Failure.class,()->client.poll(new GitHubClient.Device("x","ABCD",5000,5000)));
        assertEquals(0,calls[0]);
        time.onSleep=client::cancel;
        assertThrows(GitHubClient.Failure.class,()->client.poll(new GitHubClient.Device("x","ABCD",900000,5000)));
        assertEquals(0,calls[0]);
    }
    @Test public void terminalErrorsNeverLeakRemoteBodiesOrLoop() throws Exception {
        for(String error:Arrays.asList("access_denied","expired_token","device_flow_disabled","unknown")) {
            Time time=new Time();int[] calls={0};
            GitHubClient client=new GitHubClient((m,u,t,b,f)->{calls[0]++;return reply(new JSONObject().put("error",error).put("error_description","PRIVATE_REMOTE_BODY"));},time);
            Exception failure=assertThrows(GitHubClient.Failure.class,()->client.poll(new GitHubClient.Device("x","ABCD",900000,5000)));
            assertFalse(failure.getMessage().contains("PRIVATE_REMOTE_BODY"));assertEquals(1,calls[0]);
        }
    }
    @Test public void refreshReplacesBothTokensWithoutSecretAndAcceptsNonExpiring() throws Exception {
        GitHubClient client=new GitHubClient((m,u,t,b,f)->{
            String request=new String(b,StandardCharsets.UTF_8);
            assertTrue(request.contains("grant_type=refresh_token"));assertTrue(request.contains("refresh_token=previous"));assertFalse(request.contains("client_secret"));
            return reply(token());
        },new Time());
        JSONObject result=client.refresh(new JSONObject().put("refresh_token","previous"));
        assertEquals("synthetic_refresh",result.getString("refresh_token"));
        JSONObject response=token();response.remove("expires_in");response.remove("refresh_token");response.remove("refresh_token_expires_in");
        JSONObject nonExpiring=GitHubClient.tokens(response,1000);
        assertFalse(nonExpiring.has("expires_at"));assertFalse(nonExpiring.has("refresh_token"));
    }
    @Test public void credentialValidationRejectsBroadenedScopesAndInvalidExpiry() throws Exception {
        JSONObject response=token().put("scope","repo admin:org");
        assertThrows(GitHubClient.Failure.class,()->GitHubClient.tokens(response,1000));
        JSONObject expired=token().put("expires_in",-1);
        assertThrows(GitHubClient.Failure.class,()->GitHubClient.tokens(expired,1000));
        JSONObject header=token().put("access_token","bad\r\nheader");
        assertThrows(GitHubClient.Failure.class,()->GitHubClient.tokens(header,1000));
    }
    @Test public void untrustedVerificationUrlsAndCredentialDestinationsAreRejected() throws Exception {
        GitHubClient client=new GitHubClient((m,u,t,b,f)->reply(new JSONObject().put("device_code","x").put("user_code","ABCD")
            .put("verification_uri","https://attacker.invalid/login/device").put("interval",5).put("expires_in",900)),new Time());
        assertThrows(GitHubClient.Failure.class,client::begin);
        GitHubClient.Https https=new GitHubClient.Https();
        for(String url:Arrays.asList("http://api.github.com/user","https://attacker.invalid/user","https://github.com/other", "https://api.github.com:443/user","https://user@api.github.com/user"))
            assertThrows(GitHubClient.Failure.class,()->https.call("GET",url,"secret",null,false));
        assertThrows(GitHubClient.Failure.class,()->https.call("POST","https://github.com/login/oauth/access_token","secret",null,true));
    }
}
