package org.frankenstein.companion;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/** Public callback carries only the authorization response. PKCE/state stay in the owner activity. */
public final class GoogleDriveCallbackActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        if(getIntent().getData()!=null) startActivity(new Intent(this,GoogleDriveActivity.class)
            .setData(getIntent().getData()).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP));
        finish();
    }
}
