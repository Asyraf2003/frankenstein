package org.frankenstein.companion;

import android.content.*;
import android.database.Cursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import java.io.*;

public final class IdentityProvider extends ContentProvider {
    public boolean onCreate() { return true; }
    @Override public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (!mode.equals("r") || !uri.getPath().equals("/certificate")) throw new FileNotFoundException();
        try {
            byte[] publicCertificate = Identity.certificate().getEncoded();
            ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
            new Thread(() -> {
                try (OutputStream out = new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) { out.write(publicCertificate); }
                catch (IOException ignored) { }
            }).start();
            return pipe[0];
        } catch (Exception e) { throw new FileNotFoundException("Device identity unavailable"); }
    }
    public String getType(Uri uri) { return "application/pkix-cert"; }
    public Cursor query(Uri u, String[] p, String s, String[] a, String o) { throw new UnsupportedOperationException(); }
    public Uri insert(Uri u, ContentValues v) { throw new UnsupportedOperationException(); }
    public int delete(Uri u, String s, String[] a) { throw new UnsupportedOperationException(); }
    public int update(Uri u, ContentValues v, String s, String[] a) { throw new UnsupportedOperationException(); }
}
