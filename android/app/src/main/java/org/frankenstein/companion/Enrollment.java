package org.frankenstein.companion;

import android.app.Activity;
import android.text.InputType;
import android.view.View;
import android.widget.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/** Owner-authenticated setup form; no draft credentials are persisted. */
final class Enrollment {
    private final List<EditText> fields = new ArrayList<>();
    private boolean active = true;
    Enrollment(Activity activity, LinearLayout layout, TextView status,
               java.util.function.Consumer<JSONObject> submit) {
        status.setText("Create your ecosystem\n\nChoose your Arch account and an independent recovery passphrase. " +
            "Write the recovery passphrase outside your phone and PC. You must also export the encrypted backup; " +
            "the passphrase alone cannot recover lost data. GitHub backup is not configured by this form yet.");
        EditText username = field(activity, layout, "Arch username (lowercase)", false);
        EditText hostname = field(activity, layout, "PC hostname", false);
        EditText zone = field(activity, layout, "Timezone", false);
        zone.setText(TimeZone.getDefault().getID());
        EditText email = field(activity, layout, "Google email (optional)", false);
        EditText password = field(activity, layout, "Arch account password (12+ characters)", true);
        EditText repeatPassword = field(activity, layout, "Repeat account password", true);
        EditText diskPassword = field(activity, layout, "Disk unlock passphrase (12+ characters)", true);
        EditText repeatDisk = field(activity, layout, "Repeat disk unlock passphrase", true);
        EditText phrase = field(activity, layout, "Recovery passphrase (20+ characters)", true);
        EditText repeatPhrase = field(activity, layout, "Repeat recovery passphrase", true);
        CheckBox saved = new CheckBox(activity);
        saved.setText("I recorded my recovery passphrase outside these devices and will export the encrypted backup.");
        layout.addView(saved);
        Button create = new Button(activity);
        create.setText("Create encrypted vault");
        create.setFilterTouchesWhenObscured(true);
        create.setOnClickListener(view -> {
            if (!active) return;
            try {
                String user = username.getText().toString();
                String host = hostname.getText().toString();
                String timezone = zone.getText().toString();
                String account = password.getText().toString();
                String recovery = phrase.getText().toString();
                if (!user.matches("[a-z][a-z0-9_-]{0,30}") || user.equals("root") ||
                    !host.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?") ||
                    !Arrays.asList(TimeZone.getAvailableIDs()).contains(timezone))
                    throw new IllegalArgumentException("Check the username, hostname and timezone.");
                if (!secret(account, 12) || !account.equals(repeatPassword.getText().toString()))
                    throw new IllegalArgumentException("Account passwords must match and contain at least 12 characters.");
                if (!secret(recovery, 20) || !recovery.equals(repeatPhrase.getText().toString()) || recovery.equals(account) || !saved.isChecked())
                    throw new IllegalArgumentException("Use a separate matching recovery passphrase, at least 20 characters, and confirm its external copy.");
                String diskSecret = diskPassword.getText().toString();
                if (!secret(diskSecret, 12) || !diskSecret.equals(repeatDisk.getText().toString()))
                    throw new IllegalArgumentException("Disk unlock passphrases must match and contain at least 12 characters.");
                if (diskSecret.equals(recovery))
                    throw new IllegalArgumentException("Keep the recovery passphrase separate from the disk unlock passphrase.");
                JSONObject files = new JSONObject();
                add(files, "desired/arch.json", new JSONObject().put("username", user).put("hostname", host)
                    .put("timezone", timezone).put("packages", new JSONArray()));
                add(files, "desired/user.json", new JSONObject().put("google_email", email.getText().toString()));
                add(files, "credentials/arch-install.json", new JSONObject().put("password", account).put("disk_passphrase", diskSecret));
                JSONObject context = new JSONObject().put("revisions", new JSONObject().put("engine", BuildConfig.ENGINE_REVISION)
                    .put("state", "0000000000000000000000000000000000000000"))
                    .put("features", new JSONArray().put("initial-enrollment").put("development-engine"))
                    .put("required_owners", new JSONArray().put("credentials").put("desired"));
                JSONObject request = new JSONObject().put("context", context).put("files", files).put("recovery_passphrase", recovery);
                clear();
                create.setEnabled(false);
                submit.accept(request);
            } catch (IllegalArgumentException error) { status.setText(error.getMessage()); }
            catch (JSONException error) { status.setText("Setup could not be prepared. No vault was changed."); }
        });
        layout.addView(create);
    }
    static void add(JSONObject files, String name, JSONObject content) throws JSONException {
        files.put(name, android.util.Base64.encodeToString(content.toString().getBytes(StandardCharsets.UTF_8), android.util.Base64.NO_WRAP));
    }
    private static boolean secret(String value, int minimum) {
        return value.codePointCount(0, value.length()) >= minimum && value.length() <= 4096 &&
            value.indexOf('\n') < 0 && value.indexOf('\r') < 0 && value.indexOf('\0') < 0;
    }
    private EditText field(Activity activity, LinearLayout layout, String label, boolean secret) {
        EditText field = new EditText(activity);
        field.setHint(label);
        field.setSingleLine(true);
        field.setInputType(InputType.TYPE_CLASS_TEXT | (secret ? InputType.TYPE_TEXT_VARIATION_PASSWORD : InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD));
        field.setSaveEnabled(false);
        field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        layout.addView(field);
        fields.add(field);
        return field;
    }
    void clear() { active = false; for (EditText field : fields) field.setText(""); }
}
