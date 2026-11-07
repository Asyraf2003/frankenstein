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
    private enum Step { SIGN_IN, DESTINATION, EXISTING, CREATE, CONFIRM_CREATE, ACTION, UPLOAD, DOWNLOAD, RESULT, AFTER_UPLOAD }
    private Step step = Step.SIGN_IN;
    private String account = "", repositories = "", resultMessage = "";
    private boolean uploaded;
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
        else { home(); if (step == Step.SIGN_IN) reload(); }
    }
    @Override protected void onStop() {
        foreground=false; epoch++; busy=false;
        if (active!=null) active.cancel();
        if (repo!=null) repoName=repo.getText().toString().trim();
        if (branch!=null) branchName=branch.getText().toString().trim();
        if (digest!=null) backupDigest=digest.getText().toString().trim();
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
        TextView label = new TextView(this); label.setText(hint); layout.addView(label);
        EditText field=new EditText(this); field.setSingleLine(true); field.setHint(hint); field.setText(text);
        field.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        field.setSaveEnabled(false); layout.addView(field); return field;
    }
    private void go(Step next) {
        if (busy) return;
        step=next; home();
    }
    private void back(Step previous) { button("Back",()->go(previous)); }
    private String destination() { return account+" / "+repoName+"\nBranch: "+branchName; }
    private void home() {
        switch (step) {
            case SIGN_IN:
                screen("1. Connect GitHub\n\nAuthorize your account to store an encrypted private backup. GitHub's repo permission covers public and private repositories. Frankenstein uses only the private destination you choose.");
                button("Next: sign in to GitHub",()-> {
                    if (busy) return;
                    run(client->{expectedKit=new GitHubSession(this).currentKit();return client.begin();},value->{device=value;deviceScreen();poll();});
                });
                button("Back",this::finish);
                break;
            case DESTINATION:
                screen("2. Choose a destination\n\nSigned in as "+account+".\nUse a private repository you already own, or create one for your encrypted backups.");
                button("Use an existing repository",()->go(Step.EXISTING));
                button("Create a private repository",()->go(Step.CREATE));
                back(Step.SIGN_IN);
                break;
            case EXISTING:
                screen("2. Select your private backup destination\n\nYour repositories:\n"+repositories);
                repo=field("Repository name",repoName);
                branch=field("Existing branch name",branchName);
                button("Next",()-> {
                    if (busy) return;
                    repoName=repo.getText().toString().trim(); branchName=branch.getText().toString().trim(); selection=null;
                    if (branchName.isEmpty()) {branch.setError("Enter the branch you intend to use");branch.requestFocus();return;}
                    run(client->adapter(client).select(repoName,branchName),value->{selection=value;step=Step.ACTION;home();});
                });
                back(Step.DESTINATION);
                break;
            case CREATE:
                screen("2. Name your new private repository");
                repo=field("New repository name",repoName);
                button("Next",()-> {
                    repoName=repo.getText().toString().trim();
                    try {GitHubBackup.name(repoName);go(Step.CONFIRM_CREATE);}
                    catch(Exception error) {repo.setError("Use letters, numbers, hyphens or underscores; no spaces");}
                });
                back(Step.DESTINATION);
                break;
            case CONFIRM_CREATE:
                screen("Create this private repository?\n\n"+account+" / "+repoName+"\n\nIt will belong to your signed-in account. Existing repositories are preserved.");
                button("Create repository",()->run(client->{
                    GitHubBackup backup=adapter(client);JSONObject created=backup.create(repoName);
                    return backup.select(repoName,created.getString("default_branch"));
                },value->{selection=value;branchName=value.branch;step=Step.ACTION;home();}));
                back(Step.CREATE);
                break;
            case ACTION:
                screen("3. What would you like to do?\n\n"+destination());
                button("Save an encrypted backup",()->go(Step.UPLOAD));
                button("Download an existing backup",()->go(Step.DOWNLOAD));
                back(Step.EXISTING);
                break;
            case UPLOAD:
                screen("4. Confirm encrypted backup\n\n"+destination()+"\n\nOnly encrypted vault data and public metadata will be uploaded. Cloud limit: 8 MiB. Without a recovery passphrase, restoring requires an existing paired device key.");
                button("Upload encrypted backup",()-> {
                    if (selection==null) {step=Step.EXISTING;home();return;}
                    GitHubBackup.Selection selected=selection;
                    run(client->{
                        GitHubBackup backup=adapter(client);NativeVault vault=new NativeVault(this);String generation=vault.current();
                        Map<String,byte[]> files=GitHubBackup.capture(LocalStorage.open(this),vault,generation);
                        if (!vault.current().equals(generation)) throw new GitHubClient.Failure("Vault changed; select and upload again");
                        return backup.publish(selected,files);
                    },value->{
                        backupDigest=value;selection=null;uploaded=true;step=Step.RESULT;
                        resultMessage="Encrypted backup uploaded and downloaded bytes verified.\n\n"+destination()+"\n\nBackup SHA-256:\n"+value;
                        home();
                    });
                });
                back(Step.ACTION);
                break;
            case DOWNLOAD:
                screen("4. Download encrypted backup\n\n"+destination()+"\n\nEnter the digest of the backup you want. The next screen chooses where to save its ZIP.");
                digest=field("Backup SHA-256",backupDigest);
                button("Next: choose save location",()-> {
                    if (busy) return;
                    backupDigest=digest.getText().toString().trim();
                    if (!backupDigest.matches("[0-9a-f]{64}")) {digest.setError("Enter the backup's 64-character SHA-256");return;}
                    run(client->adapter(client).select(repoName,branchName),value->{
                        downloadSelection=value;downloadDigest=backupDigest;
                        startActivityForResult(new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip").addCategory(Intent.CATEGORY_OPENABLE)
                            .putExtra(Intent.EXTRA_TITLE,"frankenstein-github-backup.zip"),1);
                    });
                });
                back(Step.ACTION);
                break;
            case RESULT:
                screen(resultMessage);
                if (uploaded) button("Next",()->go(Step.AFTER_UPLOAD));
                else button("Done",this::finish);
                break;
            case AFTER_UPLOAD:
                screen("Backup saved. Would you like a downloaded copy too?");
                button("Download this backup",()->go(Step.DOWNLOAD));
                button("Done",this::finish);
                break;
        }
    }
    private GitHubBackup adapter(GitHubClient client) throws Exception { return new GitHubBackup(client,new GitHubSession(this).ready(client)); }
    private void reload() {
        if (busy) return;
        run(client->{
            JSONObject credential=new GitHubSession(this).load();
            if (credential==null) return null;
            return new String[]{credential.getString("login"),String.join("\n",adapter(client).repositories())};
        },value->{if(value!=null){account=value[0];repositories=value[1];step=Step.DESTINATION;home();}});
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
            device=null; expectedKit=null; account=value.getString("login"); step=Step.DESTINATION; home(); reload();
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
        },id->{
            uploaded=false;step=Step.RESULT;
            resultMessage="Encrypted backup downloaded and hashes verified.\n\n"+destination()+"\n\nSHA-256:\n"+id+
                "\n\nKeep this ZIP outside the phone. Restoring needs your recovery passphrase or a paired device key.";
            home();
        });
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
                    if (message.startsWith("GitHub conflict")) {selection=null;step=Step.EXISTING;home();}
                    status.setText(message);return;
                }
                try {done.done(result);} catch(Exception ignored) {status.setText("Result could not be displayed. Go back and try again to check the saved state.");}
            });
        });
    }
}
