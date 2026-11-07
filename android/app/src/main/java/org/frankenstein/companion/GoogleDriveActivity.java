package org.frankenstein.companion;

import android.app.*;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.WindowManager;
import android.widget.*;
import java.util.concurrent.*;
import org.json.JSONObject;

/** Owner-approved entry, external browser consent, then encrypted phone/PC replication. */
public final class GoogleDriveActivity extends Activity {
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private LinearLayout layout;
    private GoogleDriveClient.Pending pending;
    private String code;
    private boolean busy, connected;
    private volatile boolean destroyed;
    private long approvedAt;
    private String message="Connect Google Drive\n\nUse the Google account from your phone setup. Google will ask permission to read and write Drive files so Frankenstein can reuse your existing mypc folder. Only downloads, media and documents are synced on your paired PC.";
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        // Callback intents cannot create an owner-approved session. A process
        // restart loses the PKCE verifier and requires a fresh owner entry.
        if(state!=null || getIntent().getData()!=null) { finish(); return; }
        approvedAt=SystemClock.elapsedRealtime();
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        layout=new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); layout.setPadding(32,48,32,32);
        ScrollView scroll=new ScrollView(this); scroll.addView(layout); setContentView(scroll);
    }
    @Override protected void onStart() {
        super.onStart();
        if(layout==null || ((KeyguardManager)getSystemService(KEYGUARD_SERVICE)).isDeviceLocked() ||
            SystemClock.elapsedRealtime()-approvedAt>15*60*1000L) {finish();return;}
        render();
    }
    private void button(String label,Runnable action) {
        Button button=new Button(this); button.setText(label); button.setFilterTouchesWhenObscured(true);
        button.setOnClickListener(v->action.run()); layout.addView(button);
    }
    private void render() {
        if(layout==null || destroyed || isFinishing()) return;
        layout.removeAllViews(); TextView status=new TextView(this); status.setTextSize(17); status.setText(message); layout.addView(status);
        if(connected) button("Done",this::finish);
        else if(!busy) button(pending==null?"Next: connect Google Drive":"Open Google authorization",this::connect);
        if(!connected) button("Back",this::finish);
    }
    private void connect() {
        if(busy) return;
        if(pending!=null) {openBrowser();return;}
        busy=true; render();
        worker.execute(()-> {
            try {
                GoogleDriveClient.Pending created=new GoogleDriveSession(this).begin(SystemClock.elapsedRealtime());
                runOnUiThread(()-> {if(destroyed || isFinishing())return;pending=created;busy=false;openBrowser();});
            } catch(Exception error) {fail(error);}
        });
    }
    private void openBrowser() {
        try {
            message="Continue in Google\n\nAccount: "+pending.email+"\nApprove Drive access, then return here. No password or token needs to be copied.";
            render(); startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(GoogleDriveClient.authorization(pending))));
        } catch(Exception error) {fail(error);}
    }
    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if(busy || destroyed || intent.getData()==null) return;
        try {
            code=GoogleDriveClient.callback(pending,intent.getData().toString(),SystemClock.elapsedRealtime());
            busy=true; message="Google approved. Confirm ownership to save this connection in your encrypted vault."; render();
            Intent unlock=((KeyguardManager)getSystemService(KEYGUARD_SERVICE))
                .createConfirmDeviceCredentialIntent("Save Google Drive connection","Confirm ownership before saving account access");
            if(unlock==null) throw new GoogleDriveClient.Failure("Set a phone screen lock before connecting Google Drive.");
            startActivityForResult(unlock,91);
        } catch(Exception error) {fail(error);}
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(request!=91)return;
        if(result!=RESULT_OK || pending==null || code==null) {finish();return;}
        approvedAt=SystemClock.elapsedRealtime();
        message="Saving Google Drive connection securely…"; render();
        GoogleDriveClient.Pending selected=pending; String authorizationCode=code; code=null;
        worker.execute(()-> {
            try {
                JSONObject credential=new GoogleDriveClient().exchange(selected,authorizationCode,System.currentTimeMillis());
                if(destroyed)return;
                new GoogleDriveSession(this).save(selected,credential);
                runOnUiThread(()-> {
                    pending=null;busy=false;connected=true;
                    message="Google Drive connected\n\n"+selected.email+"\n\nPair with your PC to transfer the encrypted connection. Initial setup creates ~/downloads, ~/media and ~/documents and connects them to mypc on Drive. Existing cloud files are pulled first.";
                    render();
                });
            } catch(Exception error) {fail(error);}
        });
    }
    private void fail(Exception error) {
        runOnUiThread(()-> {
            if(destroyed || isFinishing())return;
            pending=null;code=null;busy=false;
            message=error instanceof GoogleDriveClient.Failure?error.getMessage():"Google connection could not be saved. Your existing vault is preserved. Please try again.";
            render();
        });
    }
    @Override protected void onStop(){if(layout!=null)layout.removeAllViews();super.onStop();}
    @Override protected void onDestroy(){destroyed=true;pending=null;code=null;worker.shutdown();super.onDestroy();}
}
