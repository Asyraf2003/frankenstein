package org.frankenstein.companion;

import android.content.Context;
import android.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.json.JSONObject;

/** Account is inherited from phone setup; successful authorization joins the same portable vault. */
final class GoogleDriveSession {
    private final BlobStore store;
    private final NativeVault vault;
    GoogleDriveSession(Context context) throws Exception { store=LocalStorage.open(context); vault=new NativeVault(context); }
    private JSONObject read(String generation,String path) throws Exception {
        byte[] data=Base64.decode(vault.inspect(store,generation,path).getJSONObject("selected").getString("base64"),Base64.NO_WRAP);
        try { return new JSONObject(new String(data,StandardCharsets.UTF_8)); }
        finally { Arrays.fill(data,(byte)0); }
    }
    GoogleDriveClient.Pending begin(long now) throws Exception {
        String generation=vault.current();
        if(generation.equals(NativeVault.EMPTY)) throw new GoogleDriveClient.Failure("Create or receive your vault first.");
        JSONObject manifest=vault.inspect(store,generation,null).getJSONObject("manifest");
        if(!manifest.getJSONObject("files").has("desired/user.json"))
            throw new GoogleDriveClient.Failure("Your vault has no Google email. Complete your phone setup first.");
        String email=read(generation,"desired/user.json").optString("google_email").trim();
        return GoogleDriveClient.begin(email,manifest.getString("kit_id"),generation,now);
    }
    void save(GoogleDriveClient.Pending pending,JSONObject credential) throws Exception {
        if(!pending.email.equalsIgnoreCase(credential.getString("account"))) throw new GoogleDriveClient.Failure("Google account changed");
        // No rotating refresh is attempted here. Failed first authorization can
        // be retried; CAS never overwrites a concurrent phone/PC generation.
        if(!vault.current().equals(pending.generation) ||
            !vault.inspect(store,pending.generation,null).getJSONObject("manifest").getString("kit_id").equals(pending.kit))
            throw new GoogleDriveClient.Failure("Your vault changed during login. Connect again.");
        vault.amendGoogleDrive(store,pending.generation,credential);
    }
}
