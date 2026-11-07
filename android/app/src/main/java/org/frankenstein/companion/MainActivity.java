package org.frankenstein.companion;

import android.app.*;
import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.view.WindowManager;
import android.widget.*;
import java.io.*;
import java.security.cert.*;

public final class MainActivity extends Activity {
    private TextView status;
    private LinearLayout layout;
    private PeerServer server;
    private X509Certificate pending;
    private boolean destroyed;
    private boolean foreground;
    private int revision;
    private boolean vaultUnlocked;
    private X509Certificate approvedPeer;
    private long approvedAt;
    private boolean startingPeer;
    private Enrollment enrollment;
    private String exporting;
    @Override protected void onStart() {
        super.onStart();
        foreground = true;
        resumeApprovedPeer();
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 72, 32, 32);
        status = new TextView(this);
        status.setTextSize(18);
        layout.addView(status);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);
        setContentView(scroll);
        show(getIntent());
    }
    @Override protected void onNewIntent(Intent intent) { super.onNewIntent(intent); show(intent); }
    private void show(Intent intent) {
        if (intent.getBooleanExtra("setup_if_empty", false)) {
            approvedPeer = null;
            show(new Intent());
            try {
                if (new NativeVault(this).current().equals(NativeVault.EMPTY))
                    status.setText("Both devices are empty. Choose Set up this phone to create your vault, then sync again from the PC.");
            } catch (Exception error) { status.setText("Protected storage is unavailable."); }
            return;
        }
        // Returning via the launcher resumes this explicitly approved in-memory
        // session. An untrusted pairing intent still goes through owner approval.
        if (intent.getStringExtra("peer_certificate") == null && approvedPeer != null) {
            resumeApprovedPeer();
            return;
        }
        revision++;
        if (enrollment != null) { enrollment.clear(); enrollment = null; }
        vaultUnlocked = false;
        approvedPeer = null;
        if (server != null) { server.close(); server = null; }
        pending = null;
        while (layout.getChildCount() > 1) layout.removeViewAt(1);
        status.setText("Frankenstein\n\nConnect USB and request pairing from the PC.\n\nDevelopment build; keep your independent recovery backup.");
        String encoded = intent.getStringExtra("peer_certificate");
        if (encoded == null) { addVaultButton(); return; }
        try {
            if (encoded.length() > 8192) throw new IOException();
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.decode(encoded, Base64.NO_WRAP)));
            certificate.checkValidity();
            certificate.verify(certificate.getPublicKey());
            String fingerprint = Identity.fingerprint(certificate);
            KeyguardManager lock = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
            if (!lock.isDeviceLocked() && new TrustedPeers(this).contains(certificate)) {
                approvedPeer = certificate;
                approvedAt = android.os.SystemClock.elapsedRealtime();
                resumeApprovedPeer();
                return;
            }
            status.setText("Approve this PC?\n\nCompare this fingerprint with the PC before accepting:\n\n" + fingerprint +
                "\n\nAn accepted device can send and retrieve your portable state while this screen is open. This PC will be remembered for reconnection while your phone is unlocked. You can forget trusted PCs at any time.");
            Button accept = new Button(this);
            accept.setText("Accept device");
            accept.setFilterTouchesWhenObscured(true);
            accept.setOnClickListener(view -> {
                pending = certificate;
                KeyguardManager keyguard = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
                Intent unlock = keyguard.createConfirmDeviceCredentialIntent("Approve Frankenstein device", "Confirm ownership before allowing transfer");
                if (unlock == null) { pending = null; status.setText("Set a device screen lock before pairing."); return; }
                accept.setEnabled(false);
                startActivityForResult(unlock, 1);
            });
            layout.addView(accept);
            Button reject = new Button(this);
            reject.setText("Reject");
            reject.setOnClickListener(view -> show(new Intent()));
            layout.addView(reject);
        } catch (Exception error) { status.setText("Invalid device certificate. Pairing rejected."); }
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 7) {
            if (result == RESULT_OK) {
                approvedPeer = null;
                if (server != null) { server.close(); server = null; }
                try { new TrustedPeers(this).forgetAll(); show(new Intent()); status.setText("Trusted PCs forgotten. New access requires approval."); }
                catch (Exception error) { status.setText("Trust reset failed. USB access is stopped."); }
            }
            return;
        }
        if (request == 6) {
            if (result == RESULT_OK) startActivity(new Intent(this, GitHubActivity.class));
            return;
        }
        if (request == 3) {
            if (result == RESULT_OK) {
                try {
                    if (!new NativeVault(this).current().equals(NativeVault.EMPTY)) {
                        status.setText("This phone already has a vault. Open it or export its backup.");
                        return;
                    }
                    while (layout.getChildCount() > 1) layout.removeViewAt(1);
                    enrollment = new Enrollment(this, layout, status, this::enroll);
                } catch (Exception error) { status.setText("Protected storage is unavailable."); }
            }
            return;
        }
        if (request == 4) {
            if (result == RESULT_OK) {
                try {
                    exporting = new NativeVault(this).current();
                    if (exporting.equals(NativeVault.EMPTY)) { exporting = null; status.setText("Create or receive a vault first."); return; }
                    Intent document = new Intent(Intent.ACTION_CREATE_DOCUMENT).setType("application/zip")
                        .addCategory(Intent.CATEGORY_OPENABLE).putExtra(Intent.EXTRA_TITLE, "frankenstein-encrypted-backup.zip");
                    startActivityForResult(document, 5);
                } catch (Exception error) { status.setText("Backup could not start."); }
            }
            return;
        }
        if (request == 5) {
            String selected = exporting;
            exporting = null;
            if (result == RESULT_OK && data != null && data.getData() != null && selected != null)
                exportBackup(selected, data.getData());
            return;
        }
        if (request == 2) {
            if (result == RESULT_OK) { vaultUnlocked = true; loadVault(null); }
            else show(new Intent());
            return;
        }
        X509Certificate peer = pending;
        pending = null;
        if (request != 1 || result != RESULT_OK || peer == null) { show(new Intent()); return; }
        try { new TrustedPeers(this).remember(peer); }
        catch (Exception error) { status.setText("PC trust could not be saved. Access remains closed."); return; }
        approvedPeer = peer;
        approvedAt = android.os.SystemClock.elapsedRealtime();
        resumeApprovedPeer();
    }
    private void resumeApprovedPeer() {
        if (!foreground || approvedPeer == null || server != null || startingPeer) return;
        KeyguardManager keyguard = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        if (keyguard.isDeviceLocked() || android.os.SystemClock.elapsedRealtime() - approvedAt > 15 * 60 * 1000L) {
            approvedPeer = null;
            show(new Intent());
            return;
        }
        X509Certificate peer = approvedPeer;
        startingPeer = true;
        while (layout.getChildCount() > 1) layout.removeViewAt(1);
        status.setText("Protecting local storage…");
        int approvedRevision = revision;
        new Thread(() -> {
            try {
                BlobStore store = LocalStorage.open(this);
                runOnUiThread(() -> {
                    startingPeer = false;
                    if (destroyed || !foreground) return;
                    if (revision != approvedRevision || approvedPeer != peer) { resumeApprovedPeer(); return; }
                    try {
                        server = new PeerServer(peer, store, new NativeVault(this), message -> runOnUiThread(() -> status.setText(message)));
                        status.setText("Device accepted. Ready for USB transfer.\n\nKeep this screen open. Closing it stops access.");
                        Button stop = new Button(this);
                        stop.setText("Stop device access");
                        stop.setOnClickListener(view -> { approvedPeer = null; show(new Intent()); });
                        layout.addView(stop);
                        addForgetButton();
                    } catch (Exception error) { status.setText("USB listener could not start. Access remains closed."); }
                });
            } catch (Exception error) { runOnUiThread(() -> {
                startingPeer = false;
                if (foreground && revision == approvedRevision) status.setText("Protected storage unavailable. Access remains closed.");
            }); }
        }).start();
    }
    @Override protected void onStop() {
        super.onStop();
        foreground = false;
        if (enrollment != null) {
            enrollment.clear(); enrollment = null;
            revision++;
            while (layout.getChildCount() > 1) layout.removeViewAt(1);
            status.setText("Setup form cleared while the app was closed. No draft secrets were saved.");
            addVaultButton();
        }
        if (vaultUnlocked) {
            vaultUnlocked = false;
            revision++;
            while (layout.getChildCount() > 1) layout.removeViewAt(1);
            status.setText("Vault locked.");
            addVaultButton();
        }
        if (server != null) { server.close(); server = null; status.setText("USB access stopped while the app is closed."); }
    }
    private void addVaultButton() {
        addForgetButton();
        Button github = new Button(this);
        github.setText("GitHub private backup");
        github.setFilterTouchesWhenObscured(true);
        github.setOnClickListener(view -> authenticate("GitHub private backup", "Confirm ownership before account access", 6));
        layout.addView(github);
        Button setup = new Button(this);
        setup.setText("Set up this phone");
        setup.setFilterTouchesWhenObscured(true);
        setup.setOnClickListener(view -> authenticate("Set up Frankenstein", "Confirm ownership before creating a vault", 3));
        layout.addView(setup);
        Button backup = new Button(this);
        backup.setText("Export encrypted backup");
        backup.setFilterTouchesWhenObscured(true);
        backup.setOnClickListener(view -> authenticate("Export recovery backup", "Confirm ownership", 4));
        layout.addView(backup);
        Button open = new Button(this);
        open.setText("Open my vault");
        open.setFilterTouchesWhenObscured(true);
        open.setOnClickListener(view -> {
            KeyguardManager keyguard = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
            Intent unlock = keyguard.createConfirmDeviceCredentialIntent("Open Frankenstein vault", "Confirm ownership");
            if (unlock != null) startActivityForResult(unlock, 2);
            else status.setText("Set a device screen lock before opening the vault.");
        });
        layout.addView(open);
    }
    private void addForgetButton() {
        Button forget = new Button(this);
        forget.setText("Forget trusted PCs");
        forget.setFilterTouchesWhenObscured(true);
        forget.setOnClickListener(view -> authenticate("Forget trusted PCs", "Future connections will need approval again", 7));
        layout.addView(forget);
    }
    private void authenticate(String title, String message, int request) {
        KeyguardManager keyguard = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);
        Intent unlock = keyguard.createConfirmDeviceCredentialIntent(title, message);
        if (unlock == null) status.setText("Set a device screen lock first.");
        else startActivityForResult(unlock, request);
    }
    private void enroll(org.json.JSONObject request) {
        boolean recoveryEnabled = !request.optString("recovery_passphrase").isEmpty();
        enrollment = null;
        while (layout.getChildCount() > 1) layout.removeViewAt(1);
        status.setText("Creating and verifying your encrypted vault…");
        int selectedRevision = revision;
        new Thread(() -> {
            boolean success = false;
            try {
                new NativeVault(this).enroll(LocalStorage.open(this), request);
                success = true;
            } catch (Exception error) { /* No input values in diagnostics. */ }
            finally { request.remove("recovery_passphrase"); request.remove("files"); }
            boolean accepted = success;
            runOnUiThread(() -> {
                if (destroyed || revision != selectedRevision) return;
                status.setText(accepted ? (recoveryEnabled ?
                    "Vault created. Export its encrypted backup and keep your recovery passphrase separately. GitHub backup still needs setup." :
                    "Vault created without a recovery passphrase. Encrypted backups require an existing device key or paired copy. GitHub backup can now be configured.") :
                    "Setup failed or another vault became active. Existing state was preserved.");
                addVaultButton();
            });
        }, "frankenstein-enrollment").start();
    }
    private void exportBackup(String selected, android.net.Uri uri) {
        status.setText("Verifying and exporting encrypted backup…");
        new Thread(() -> {
            boolean success = false;
            try (OutputStream target = getContentResolver().openOutputStream(uri, "wt")) {
                if (target == null) throw new IOException();
                BackupExport.write(LocalStorage.open(this), new NativeVault(this), selected, target);
                success = true;
            } catch (Exception error) { /* Partial provider output must not be announced as a backup. */ }
            boolean complete = success;
            runOnUiThread(() -> {
                if (!destroyed) status.setText(complete ? "Encrypted backup exported. Keep it outside this phone. Recovery requires your optional passphrase or an existing device key, depending on your setup." :
                    "Export failed. The selected file may be incomplete; export again. Your local vault is unchanged.");
            });
        }, "frankenstein-backup-export").start();
    }
    private void loadVault(String selected) {
        int requestedRevision = revision;
        status.setText("Verifying your vault…");
        new Thread(() -> {
            try {
                NativeVault vault = new NativeVault(this);
                String id = vault.current();
                if (id.equals(NativeVault.EMPTY)) throw new IOException("No provisioned vault");
                org.json.JSONObject result = vault.inspect(LocalStorage.open(this), id, selected);
                runOnUiThread(() -> {
                    if (!foreground || !vaultUnlocked || revision != requestedRevision) return;
                    while (layout.getChildCount() > 1) layout.removeViewAt(1);
                    try {
                        if (selected != null) {
                            byte[] bytes = Base64.decode(result.getJSONObject("selected").getString("base64"), Base64.NO_WRAP);
                            status.setText(selected + "\n\n" + new String(bytes, java.nio.charset.StandardCharsets.UTF_8));
                            java.util.Arrays.fill(bytes, (byte)0);
                            Button back = new Button(this);
                            back.setText("Back to vault");
                            back.setOnClickListener(view -> loadVault(null));
                            layout.addView(back);
                        } else {
                            org.json.JSONObject files = result.getJSONObject("manifest").getJSONObject("files");
                            status.setText("Vault ready\n" + files.length() + " verified items.\nUpdated: " +
                                result.getJSONObject("manifest").getString("created_at") + "\nThis phone can provide state to a new PC.");
                            java.util.Iterator<String> names = files.keys();
                            while (names.hasNext()) {
                                String name = names.next();
                                if (files.getJSONObject(name).getLong("size") > 1024 * 1024) continue;
                                Button entry = new Button(this);
                                entry.setText(name);
                                entry.setOnClickListener(view -> { if (vaultUnlocked) loadVault(name); });
                                layout.addView(entry);
                            }
                        }
                    } catch (Exception error) { status.setText("Vault result could not be displayed."); }
                });
            } catch (Exception error) {
                runOnUiThread(() -> {
                    if (foreground && vaultUnlocked && revision == requestedRevision)
                        status.setText("Vault unavailable. Receive a provisioning package or restore your encrypted backup.");
                });
            }
        }).start();
    }
    @Override protected void onDestroy() {
        destroyed = true;
        if (server != null) server.close();
        super.onDestroy();
    }
}
