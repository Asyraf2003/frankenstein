package org.frankenstein.companion;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.net.ssl.HttpsURLConnection;
import org.json.*;

/** No caller-supplied hosts, redirects, secrets in URLs, or remote error bodies. */
final class GitHubClient {
    static final String CLIENT_ID = "Ov23lidnxATbcD2G4GU0";
    static final int MAX_RESPONSE = 24 * 1024 * 1024;
    interface Transport { Reply call(String method, String url, String token, byte[] body, boolean form) throws Exception; }
    interface Clock { long millis(); void sleep(long millis) throws InterruptedException; }
    static final class Reply {
        final int status; final String body;
        Reply(int status, String body) { this.status = status; this.body = body; }
        JSONObject object() throws Exception { return new JSONObject(body); }
    }
    static final class Failure extends IOException { Failure(String message) { super(message); } }
    static final class Https implements Transport {
        private volatile HttpsURLConnection active;
        private volatile boolean cancelled;
        void cancel() { cancelled = true; HttpsURLConnection c = active; if (c != null) c.disconnect(); }
        public Reply call(String method, String address, String token, byte[] body, boolean form) throws Exception {
            URL url = new URL(address);
            if (!url.getProtocol().equals("https") || url.getPort() != -1 || url.getUserInfo() != null || url.getRef() != null ||
                !(url.getHost().equals("api.github.com") || (url.getHost().equals("github.com") &&
                (url.getPath().equals("/login/device/code") || url.getPath().equals("/login/oauth/access_token")))))
                throw new Failure("GitHub endpoint rejected");
            if (token != null && !url.getHost().equals("api.github.com")) throw new Failure("Credential destination rejected");
            if (cancelled) throw new Failure("Cancelled");
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            active = connection;
            Timer watchdog = new Timer(true);
            watchdog.schedule(new TimerTask() { public void run() { connection.disconnect(); } }, 45000);
            try {
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(15000); connection.setReadTimeout(15000);
                connection.setRequestMethod(method);
                connection.setRequestProperty("Accept", form ? "application/json" : "application/vnd.github+json");
                connection.setRequestProperty("User-Agent", "Frankenstein-Companion");
                connection.setRequestProperty("X-GitHub-Api-Version", "2022-11-28");
                if (token != null) connection.setRequestProperty("Authorization", "Bearer " + token);
                if (body != null) {
                    if (body.length > MAX_RESPONSE) throw new Failure("GitHub request exceeds limit");
                    connection.setDoOutput(true);
                    connection.setRequestProperty("Content-Type", form ? "application/x-www-form-urlencoded" : "application/json");
                    connection.setFixedLengthStreamingMode(body.length);
                    try (OutputStream output = connection.getOutputStream()) { output.write(body); }
                }
                int status = connection.getResponseCode();
                if (status >= 300 && status < 400) throw new Failure("GitHub redirect rejected");
                if (cancelled) throw new Failure("Cancelled");
                InputStream source = status < 400 ? connection.getInputStream() : connection.getErrorStream();
                if (source == null) return new Reply(status, "{}");
                try (InputStream input = source; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                    byte[] buffer = new byte[8192]; int count;
                    long deadline = System.nanoTime() + 30000000000L;
                    while ((count = input.read(buffer)) != -1) {
                        if (cancelled || System.nanoTime() > deadline) throw new Failure("GitHub request cancelled or timed out");
                        if (output.size() + count > MAX_RESPONSE) throw new Failure("GitHub response exceeds limit");
                        output.write(buffer, 0, count);
                    }
                    return new Reply(status, output.toString("UTF-8"));
                }
            } finally { watchdog.cancel(); active = null; connection.disconnect(); }
        }
    }
    private final Transport transport;
    private final Clock clock;
    private volatile boolean cancelled;
    GitHubClient() { this(new Https(), new Clock() {
        public long millis() { return android.os.SystemClock.elapsedRealtime(); }
        public void sleep(long millis) throws InterruptedException { Thread.sleep(millis); }
    }); }
    GitHubClient(Transport transport, Clock clock) { this.transport = transport; this.clock = clock; }
    void cancel() { cancelled = true; if (transport instanceof Https) ((Https)transport).cancel(); }
    void check() throws Failure { if (cancelled || Thread.currentThread().isInterrupted()) throw new Failure("Cancelled"); }
    private JSONObject oauth(String path, String... pairs) throws Exception {
        check(); StringBuilder form = new StringBuilder();
        for (int i = 0; i < pairs.length; i += 2) {
            if (form.length() != 0) form.append('&');
            form.append(pairs[i]).append('=').append(URLEncoder.encode(pairs[i+1], "UTF-8"));
        }
        byte[] body = form.toString().getBytes(StandardCharsets.UTF_8);
        try {
            Reply response = transport.call("POST", "https://github.com" + path, null, body, true);
            check();
            if (response.status != 200) throw new Failure("GitHub authorization request failed (HTTP " + response.status + ")");
            return response.object();
        } finally { Arrays.fill(body, (byte)0); }
    }
    static final class Device {
        final String code, userCode; final long deadline; long interval;
        Device(String code, String userCode, long deadline, long interval) { this.code=code; this.userCode=userCode; this.deadline=deadline; this.interval=interval; }
    }
    Device begin() throws Exception {
        JSONObject response = oauth("/login/device/code", "client_id", CLIENT_ID, "scope", "repo");
        if (response.has("error")) throw authorizationError(response);
        String url = response.getString("verification_uri");
        String code = response.getString("device_code"), userCode = response.getString("user_code");
        int seconds = response.getInt("expires_in"), interval = response.getInt("interval");
        if (!url.equals("https://github.com/login/device") || !code.matches("[A-Za-z0-9_-]{1,256}") ||
            !userCode.matches("[A-Za-z0-9-]{4,32}") || seconds < 1 || seconds > 1800 || interval < 1 || interval > 60)
            throw new Failure("Invalid GitHub device authorization response");
        return new Device(code, userCode, clock.millis() + seconds * 1000L, interval * 1000L);
    }
    JSONObject poll(Device device) throws Exception {
        while (true) {
            check();
            if (clock.millis() + device.interval >= device.deadline) throw new Failure("GitHub code expired; sign in again");
            long wake = clock.millis() + device.interval;
            while (clock.millis() < wake) { check(); clock.sleep(Math.min(250, wake-clock.millis())); }
            JSONObject response = oauth("/login/oauth/access_token", "client_id", CLIENT_ID, "device_code", device.code,
                "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
            if (clock.millis() >= device.deadline) throw new Failure("GitHub code expired; sign in again");
            String error = response.optString("error", "");
            if (error.equals("authorization_pending")) continue;
            if (error.equals("slow_down")) { device.interval += 5000; continue; }
            if (!error.isEmpty()) throw authorizationError(response);
            return tokens(response, System.currentTimeMillis());
        }
    }
    JSONObject refresh(JSONObject previous) throws Exception {
        JSONObject response = oauth("/login/oauth/access_token", "client_id", CLIENT_ID,
            "grant_type", "refresh_token", "refresh_token", previous.getString("refresh_token"));
        if (response.has("error")) throw authorizationError(response);
        return tokens(response, System.currentTimeMillis());
    }
    private static Failure authorizationError(JSONObject response) {
        switch (response.optString("error")) {
            case "access_denied": return new Failure("GitHub authorization declined");
            case "expired_token": return new Failure("GitHub code expired; sign in again");
            case "device_flow_disabled": return new Failure("GitHub device flow is disabled for this application");
            default: return new Failure("GitHub authorization failed; sign in again");
        }
    }
    static JSONObject tokens(JSONObject response, long now) throws Exception {
        String access = response.getString("access_token");
        if (!access.matches("[A-Za-z0-9_]{1,512}") || !response.optString("token_type").equalsIgnoreCase("bearer"))
            throw new Failure("Invalid GitHub credential response");
        Set<String> scopes = new HashSet<>(Arrays.asList(response.optString("scope").split("[ ,]+")));
        if (!scopes.contains("repo") || scopes.stream().anyMatch(s -> !s.equals("repo") && !s.equals("offline_access")))
            throw new Failure("GitHub permission mismatch; authorize only the requested repository permission");
        JSONObject result = new JSONObject().put("access_token", access).put("scope", response.getString("scope"));
        if (response.has("expires_in")) result.put("expires_at", expiry(response.getLong("expires_in"), now));
        if (response.has("refresh_token")) {
            String refresh = response.getString("refresh_token");
            if (!refresh.matches("[A-Za-z0-9_]{1,512}")) throw new Failure("Invalid GitHub refresh credential");
            result.put("refresh_token", refresh).put("refresh_expires_at", expiry(response.getLong("refresh_token_expires_in"), now));
        }
        return result;
    }
    private static long expiry(long seconds, long now) throws Failure {
        if (seconds < 1 || seconds > 366L * 86400) throw new Failure("Invalid credential expiry");
        return now + seconds * 1000;
    }
    Reply api(String method, String path, String token, JSONObject data) throws Exception {
        check();
        if (!path.startsWith("/") || path.contains("..") || path.contains("#") || path.contains("\\")) throw new Failure("Invalid GitHub API path");
        byte[] body = data == null ? null : data.toString().getBytes(StandardCharsets.UTF_8);
        try { Reply response = transport.call(method, "https://api.github.com"+path, token, body, false); check(); return response; }
        finally { if (body != null) Arrays.fill(body, (byte)0); }
    }
    JSONObject object(String method, String path, String token, JSONObject data) throws Exception {
        Reply response = api(method, path, token, data);
        if (response.status < 200 || response.status >= 300) throw new Failure(response.status == 409 || response.status == 422 ?
            "GitHub conflict; reload the selected branch before trying again" : "GitHub request failed (HTTP " + response.status + ")");
        return response.object();
    }
}
