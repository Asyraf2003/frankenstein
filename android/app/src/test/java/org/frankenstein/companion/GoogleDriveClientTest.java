package org.frankenstein.companion;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.JSONObject;

public class GoogleDriveClientTest {
    private GoogleDriveClient.Pending pending() throws Exception {
        return GoogleDriveClient.begin("123-fixture.apps.googleusercontent.com","fixture@example.test","kit","generation",1000);
    }
    private String callback(GoogleDriveClient.Pending p,String suffix) {
        return p.redirect+"?state="+p.state+suffix;
    }
    private JSONObject tokens() throws Exception {
        return new JSONObject().put("access_token","synthetic-access").put("refresh_token","synthetic-refresh")
            .put("token_type","Bearer").put("expires_in",3600).put("scope","openid email "+GoogleDriveClient.DRIVE_SCOPE);
    }
    @Test public void pkceMatchesRfcVectorAndEmailIsInherited() throws Exception {
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",GoogleDriveClient.challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        GoogleDriveClient.Pending p=pending(); String url=GoogleDriveClient.authorization(p);
        assertTrue(url.startsWith("https://accounts.google.com/o/oauth2/v2/auth?"));
        assertTrue(url.contains("code_challenge_method=S256"));
        assertTrue(url.contains("login_hint=fixture%40example.test"));
        assertFalse(url.contains(p.verifier));
        assertNotEquals(pending().state,p.state);
    }
    @Test public void callbackBindsStateRedirectExpiryAndSingleUse() throws Exception {
        GoogleDriveClient.Pending p=pending();
        assertThrows(GoogleDriveClient.Failure.class,()->GoogleDriveClient.callback(p,p.redirect+"?state=wrong&code=fixture",1100));
        assertThrows(GoogleDriveClient.Failure.class,()->GoogleDriveClient.callback(p,callback(p,"&state=duplicate&code=fixture"),1100));
        assertThrows(GoogleDriveClient.Failure.class,()->GoogleDriveClient.callback(p,"https://example.test?state="+p.state+"&code=fixture",1100));
        assertThrows(GoogleDriveClient.Failure.class,()->GoogleDriveClient.callback(p,callback(p,"&code=fixture#fragment"),1100));
        assertEquals("fixture",GoogleDriveClient.callback(p,callback(p,"&code=fixture"),1100));
        assertThrows(GoogleDriveClient.Failure.class,()->GoogleDriveClient.callback(p,callback(p,"&code=fixture"),1100));
        GoogleDriveClient.Pending expired=pending();
        assertThrows(GoogleDriveClient.Failure.class,()->GoogleDriveClient.callback(expired,callback(expired,"&code=fixture"),602000));
    }
    @Test public void cancellationDoesNotReturnCode() throws Exception {
        GoogleDriveClient.Pending p=pending();
        assertThrows(GoogleDriveClient.Failure.class,()->GoogleDriveClient.callback(p,callback(p,"&error=access_denied"),1100));
    }
    @Test public void exchangeUsesPrivatePostAndVerifiedMatchingEmail() throws Exception {
        GoogleDriveClient.Pending p=pending();
        GoogleDriveClient client=new GoogleDriveClient((url,token,body)-> {
            if(body!=null) {
                assertEquals("https://oauth2.googleapis.com/token",url); assertNull(token);
                String form=new String(body,java.nio.charset.StandardCharsets.UTF_8);
                assertTrue(form.contains("code_verifier="+p.verifier)); assertTrue(form.contains("code=fixture"));
                assertFalse(form.contains("client_secret")); return tokens();
            }
            assertEquals("https://openidconnect.googleapis.com/v1/userinfo",url); assertEquals("synthetic-access",token);
            return new JSONObject().put("email","fixture@example.test").put("email_verified",true);
        });
        JSONObject result=client.exchange(p,"fixture",0);
        assertEquals("synthetic-refresh",result.getString("refresh_token"));
        assertEquals("1970-01-01T01:00:00Z",result.getString("expiry"));
        assertEquals("fixture@example.test",result.getString("account"));
    }
    @Test public void accountMismatchNeverProducesPortableCredential() throws Exception {
        GoogleDriveClient client=new GoogleDriveClient((url,token,body)->body!=null?tokens():
            new JSONObject().put("email","other@example.test").put("email_verified",true));
        assertThrows(GoogleDriveClient.Failure.class,()->client.exchange(pending(),"fixture",0));
    }
    @Test public void missingOfflineAccessOrDriveScopeFailsBeforeUserinfo() throws Exception {
        for(String missing:new String[]{"refresh_token","scope"}) {
            JSONObject response=tokens(); response.remove(missing);
            GoogleDriveClient client=new GoogleDriveClient((url,token,body)-> {
                assertNotNull(body);return response;
            });
            assertThrows(GoogleDriveClient.Failure.class,()->client.exchange(pending(),"fixture",0));
        }
    }
}
