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
    @Override protected void onStart() { super.onStart(); foreground = true; }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE | WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 72, 32, 32);
        status = new TextView(this);
        status.setTextSize(18);
        layout.addView(status);
        setContentView(layout);
        show(getIntent());
    }
    @Override protected void onNewIntent(Intent intent) { super.onNewIntent(intent); show(intent); }
    private void show(Intent intent) {
        revision++;
        if (server != null) { server.close(); server = null; }
        pending = null;
        while (layout.getChildCount() > 1) layout.removeViewAt(1);
        status.setText("Frankenstein\n\nConnect USB and request pairing from the PC.\n\nDevelopment build; keep your independent recovery backup.");
        String encoded = intent.getStringExtra("peer_certificate");
        if (encoded == null) return;
        try {
            if (encoded.length() > 8192) throw new IOException();
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.decode(encoded, Base64.NO_WRAP)));
            certificate.checkValidity();
            certificate.verify(certificate.getPublicKey());
            String fingerprint = Identity.fingerprint(certificate);
            status.setText("Approve this PC?\n\nCompare this fingerprint with the PC before accepting:\n\n" + fingerprint +
                "\n\nAn accepted device can send and retrieve your portable state while this screen is open.");
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
        X509Certificate peer = pending;
        pending = null;
        if (request != 1 || result != RESULT_OK || peer == null) { show(new Intent()); return; }
        while (layout.getChildCount() > 1) layout.removeViewAt(1);
        status.setText("Protecting local storage…");
        int approvedRevision = revision;
        new Thread(() -> {
            try {
                BlobStore store = LocalStorage.open(this);
                runOnUiThread(() -> {
                    if (destroyed || !foreground || revision != approvedRevision) return;
                    try {
                        server = new PeerServer(peer, store, message -> runOnUiThread(() -> status.setText(message)));
                        status.setText("Device accepted. Ready for USB transfer.\n\nKeep this screen open. Closing it stops access.");
                        Button stop = new Button(this);
                        stop.setText("Stop device access");
                        stop.setOnClickListener(view -> show(new Intent()));
                        layout.addView(stop);
                    } catch (Exception error) { status.setText("USB listener could not start. Access remains closed."); }
                });
            } catch (Exception error) { runOnUiThread(() -> status.setText("Protected storage unavailable. Access remains closed.")); }
        }).start();
    }
    @Override protected void onStop() {
        super.onStop();
        foreground = false;
        if (server != null) { server.close(); server = null; status.setText("Access stopped. Request pairing again to reconnect."); }
    }
    @Override protected void onDestroy() {
        destroyed = true;
        if (server != null) server.close();
        super.onDestroy();
    }
}
