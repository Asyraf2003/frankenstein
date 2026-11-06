package org.frankenstein.companion;

import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;

final class PeerServer implements AutoCloseable {
    static final int PORT = 48173;
    private final SSLServerSocket listener;
    private volatile SSLSocket current;
    private volatile boolean stopped;
    PeerServer(X509Certificate peer, BlobStore store, java.util.function.Consumer<String> status) throws Exception {
        listener = (SSLServerSocket) Identity.context(peer).getServerSocketFactory().createServerSocket();
        listener.setReuseAddress(true);
        listener.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), PORT), 1);
        listener.setEnabledProtocols(new String[]{"TLSv1.3"});
        listener.setNeedClientAuth(true);
        new Thread(() -> {
            while (!stopped) {
                try (SSLSocket socket = (SSLSocket) listener.accept()) {
                    synchronized (this) {
                        if (stopped) return;
                        current = socket;
                    }
                    socket.setSoTimeout(60000);
                    socket.startHandshake();
                    DataInputStream input = new DataInputStream(socket.getInputStream());
                    DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                    if (input.readInt() != 0x46524b31) throw new IOException("Protocol mismatch");
                    int operation = input.readUnsignedByte();
                    byte[] digestBytes = new byte[32];
                    input.readFully(digestBytes);
                    String id = Identity.hex(digestBytes);
                    if (operation == 1) {
                        status.accept("Receiving encrypted state…");
                        store.put(id, input.readLong(), input);
                        output.writeByte(0);
                    } else if (operation == 2) {
                        // Fully authenticate local storage before exposing an object.
                        store.verify(id);
                        try (DataInputStream object = store.open(id)) {
                            long length = object.readLong();
                            output.writeByte(0);
                            output.writeLong(length);
                            MessageDigest digest = MessageDigest.getInstance("SHA-256");
                            BlobStore.copy(object, output, length, digest);
                            if (object.read() != -1 || !Identity.hex(digest.digest()).equals(id)) throw new IOException("Corrupt storage");
                            output.writeByte(0);
                        }
                    } else throw new IOException("Unknown operation");
                    output.flush();
                    status.accept("Transfer verified. Ready.");
                } catch (Exception error) {
                    if (!stopped) status.accept("Transfer rejected or interrupted. Retry is safe.");
                } finally { current = null; }
            }
        }, "frankenstein-usb").start();
    }
    public synchronized void close() {
        stopped = true;
        try { listener.close(); } catch (IOException ignored) { }
        SSLSocket socket = current;
        if (socket != null) try { socket.close(); } catch (IOException ignored) { }
    }
}
