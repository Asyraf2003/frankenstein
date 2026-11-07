package org.frankenstein.companion;

import android.app.*;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.WindowManager;
import android.widget.*;
import java.io.OutputStream;
import java.util.*;
import java.util.concurrent.*;
import org.json.JSONObject;

/** Entered only after MainActivity's owner credential confirmation. */
public final class GitHubActivity extends Activity {
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private LinearLayout layout;
    private TextView status;
    private EditText repo,branch,digest;
    private volatile GitHubClient active;
    private GitHubClient.Device device;
    private String expectedKit, repoName="", branchName="", backupDigest="";
    private GitHubBackup.Selection selection, downloadSelection;
    private String downloadDigest;
    private Uri downloadTarget;
    private boolean foreground,busy;
    private int epoch;
    private long approvedAt;
    interface Action<T> { T run(GitHubClient client) throws Exception; }
    interface Done<T> { void done(T value) throws Exception; }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        // Activity/process recreation must not resurrect an authenticated UI.
        if (state!=null) { finish(); return; }
        approvedAt=android.os.SystemClock.elapsedRealtime();
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        layout=new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); layout.setPadding(32,48,32,32);
        ScrollView scroll=new ScrollView(this); scroll.addView(layout); setContentView(scroll);
    }
    @Override protected void onStart() {
        super.onStart();
        if (layout==null || ((KeyguardManager)getSystemService(KEYGUARD_SERVICE)).isDeviceLocked() ||
            android.os.SystemClock.elapsedRealtime()-approvedAt>15*60*1000L) { finish(); return; }
        foreground=true;
        if (downloadTarget!=null) { home(); download(); }
        else if (device!=null) { deviceScreen(); poll(); }
        else { home(); reload(); }
    }
    @Override protected void onStop() {
        foreground=false; epoch++; busy=false;
        if (active!=null) active.cancel();
        if (repo!=null) { repoName=repo.getText().toString().trim(); branchName=branch.getText().toString().trim(); backupDigest=digest.getText().toString().trim(); }
        if (layout!=null) layout.removeAllViews(); repo=null; branch=null; digest=null;
        super.onStop();
    }
    @Override protected void onDestroy() { if (active!=null) active.cancel(); worker.shutdown(); super.onDestroy(); }
    private void screen(String message) {
        layout.removeAllViews(); repo=null; branch=null; digest=null;
        status=new TextView(this); status.setTextSize(17); status.setText(message); layout.addView(status);
    }
    private Button button(String title,Runnable action) {
        Button button=new Button(this); button.setText(title); button.setFilterTouchesWhenObscured(true);
        button.setOnClickListener(v->action.run()); layout.addView(button); return button;
    }
    private EditText field(String hint,String text) {
        EditText field=new EditText(this); field.setSingleLine(true); field.setHint(hint); field.setText(text);
        field.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        field.setSaveEnabled(false); layout.addView(field); return field;
    }
    private void home() {
        screen("GitHub private backup");
        TextView disclosure = new TextView(this);
        disclosure.setText("Only encrypted vault data and public metadata are uploaded. Recovery passphrase is optional; without one, keep an existing device key or paired copy. Cloud limit: 8 MiB.\n\nGitHub's repo permission covers public and private repositories; Frankenstein writes only the private repository and branch you select.");
        layout.addView(disclosure);
        button("Sign in / authorize this device",()->{
            if (busy) return;
            run(client->{ expectedKit=new GitHubSession(this).currentKit(); return client.begin(); },value->{ device=value; deviceScreen(); poll(); });
        });
        button("Reload my private repositories",this::reload);
        repo=field("Private repository name",repoName); branch=field("Existing branch (blank = default)",branchName);
        button("Inspect repository and branch",()->{
            if (busy) return;
            String name=repo.getText().toString().trim(), ref=branch.getText().toString().trim();
            selection=null;
            run(client->adapter(client).select(name,ref), selected->{
                selection=selected; repoName=name; branchName=selected.branch; branch.setText(branchName);
                status.setText("Selected "+selected.repository+" / "+selected.branch+"\nCommit "+selected.parent+"\n\nUpload uses this exact prior commit. Other repository files are preserved.");
            });
        });
        button("Create my private repository",()->{
            if (busy) return;
            String name=repo.getText().toString().trim();
            new AlertDialog.Builder(this).setTitle("Create private repository?")
                .setMessage("Create "+name+" in your signed-in GitHub account. Existing repositories are never replaced.")
                .setNegativeButton("Cancel",null).setPositiveButton("Create",(dialog,which)->run(client->{
                    GitHubBackup backup=adapter(client); JSONObject created=backup.create(name);
                    return backup.select(name,created.getString("default_branch"));
                },selected->{selection=selected; repoName=name; branchName=selected.branch; branch.setText(branchName); status.setText("Private repository created and selected: "+selected.repository); })).show();
        });
        button("Upload encrypted backup",()->{
            if (busy) return;
            GitHubBackup.Selection selected=chosen(); if (selected==null) return;
            new AlertDialog.Builder(this).setTitle("Upload encrypted backup?").setMessage(selected.repository+"\nBranch: "+selected.branch+"\nPrior commit: "+selected.parent)
                .setNegativeButton("Cancel",null).setPositiveButton("Upload",(dialog,which)->run(client->{
                    GitHubBackup backup=adapter(client); NativeVault vault=new NativeVault(this); String generation=vault.current();
                    Map<String,byte[]> files=GitHubBackup.capture(LocalStorage.open(this),vault,generation);
                    if (!vault.current().equals(generation)) throw new GitHubClient.Failure("Vault changed; select and upload again");
                    return backup.publish(selected,files);
                },value->{backupDigest=value; digest.setText(value); selection=null;
                    status.setText("Encrypted backup uploaded and downloaded bytes verified.\nBackup digest:\n"+value+"\n\nKeep this digest externally. Inspect the branch again before another upload or download.");})).show();
        });
        digest=field("Backup SHA-256 for recovery download",backupDigest);
        button("Download recovery ZIP from GitHub",()->{
            if (busy) return;
            GitHubBackup.Selection selected=chosen(); if (selected==null) return;
            String value=digest.getText().toString().trim();
            if (!value.matches("[0-9a-f]{64}")) {status.setText("Enter the backup's 64-character SHA-256 digest.");return;}
            downloadSelection=selected; downloadDigest=value;
            startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE)
                .putExtra(Intent.EXTRA_TITLE,"frankenstein-github-backup.zip"),1);
        });
        button("Close GitHub setup",this::finish);
    }
    private GitHubBackup.Selection chosen() {
        if (selection==null || !selection.repository.endsWith("/"+repo.getText().toString().trim()) || !selection.branch.equals(branch.getText().toString().trim())) {
            status.setText("Inspect the repository and branch first."); return null;
        }
        return selection;
    }
    private GitHubBackup adapter(GitHubClient client) throws Exception { return new GitHubBackup(client,new GitHubSession(this).ready(client)); }
    private void reload() {
        if (busy) return;
        run(client->{
            GitHubSession session=new GitHubSession(this); JSONObject credential=session.load();
            if (credential==null) return "Sign in to GitHub to choose your private repository.";
            return "Signed in as "+credential.getString("login")+"\nYour writable private repositories:\n"+String.join("\n",adapter(client).repositories());
        },value->status.setText(value));
    }
    private void deviceScreen() {
        screen("Authorize Frankenstein on GitHub\n\nVisit https://github.com/login/device\nEnter code: "+device.userCode+
            "\n\nApprove only if the application name and repo permission match. You can open GitHub here or use another device.");
        button("Open GitHub authorization",()->startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse("https://github.com/login/device"))));
        button("Cancel sign-in",()->{ if(active!=null)active.cancel(); device=null; expectedKit=null; epoch++; busy=false; home(); });
    }
    private void poll() {
        GitHubClient.Device requested=device; String identity=expectedKit;
        run(client->{JSONObject tokens=client.poll(requested); return new GitHubSession(this).signIn(client,tokens,identity);},value->{
            device=null; expectedKit=null; home(); status.setText("Signed in as "+value.getString("login")+". Credentials saved inside your encrypted portable vault."); reload();
        });
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if (request==1 && result==RESULT_OK && data!=null) downloadTarget=data.getData();
        else {downloadSelection=null;downloadDigest=null;}
    }
    private void download() {
        Uri uri=downloadTarget; GitHubBackup.Selection selected=downloadSelection; String value=downloadDigest;
        downloadTarget=null;downloadSelection=null;downloadDigest=null;
        run(client->{
            Map<String,byte[]> files=adapter(client).download(selected,value);
            try (OutputStream output=getContentResolver().openOutputStream(uri,"wt")) {
                if (output==null) throw new java.io.IOException(); GitHubBackup.recoveryZip(files,output);
            }
            return value;
        },id->status.setText("GitHub recovery ZIP downloaded and hashes verified.\nDigest: "+id+
            "\nUse recover-backup with your optional recovery passphrase or an existing device identity (--identity). This download does not replace the phone's vault."));
    }
    private <T> void run(Action<T> action,Done<T> done) {
        if (busy || !foreground) return;
        if (((KeyguardManager)getSystemService(KEYGUARD_SERVICE)).isDeviceLocked() ||
            android.os.SystemClock.elapsedRealtime()-approvedAt>15*60*1000L) { finish(); return; }
        busy=true; int requested=epoch; GitHubClient client=new GitHubClient(); active=client;
        worker.execute(()->{
            T value=null; String error=null;
            try { value=action.run(client); }
            catch (Exception failure) { error=failure instanceof GitHubClient.Failure ? failure.getMessage() : "Operation failed. No backup is confirmed; a selected output file may be incomplete. Retry or sign in again."; }
            T result=value; String message=error;
            runOnUiThread(()->{
                if (!foreground || epoch!=requested) return;
                busy=false;
                if (message!=null) {
                    if (device!=null) {device=null;expectedKit=null;home();}
                    status.setText(message);return;
                }
                try {done.done(result);} catch(Exception ignored) {status.setText("Result could not be displayed. Reload to check the saved state.");}
            });
        });
    }
}
