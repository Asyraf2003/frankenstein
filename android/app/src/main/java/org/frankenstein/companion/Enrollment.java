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
        status.setText("Create your ecosystem\n\nChoose your Arch login/sudo account. Recovery passphrase is optional. " +
            "Without it, encrypted backups require an existing device key or paired copy; losing all keys makes them unrecoverable. " +
            "GitHub backup can be configured after setup.");
        EditText username = field(activity, layout, "Arch username (lowercase)", false);
        EditText hostname = field(activity, layout, "PC hostname", false);
        EditText zone = field(activity, layout, "Timezone", false);
        zone.setText(TimeZone.getDefault().getID());
        EditText email = field(activity, layout, "Google email (optional)", false);
        EditText password = field(activity, layout, "Arch login/sudo password (4+ characters)", true);
        EditText repeatPassword = field(activity, layout, "Repeat account password", true);
        EditText diskPassword = field(activity, layout, "Disk unlock passphrase (12+ characters)", true);
        EditText repeatDisk = field(activity, layout, "Repeat disk unlock passphrase", true);
        CheckBox recoveryEnabled = new CheckBox(activity);
        recoveryEnabled.setText("Add an optional recovery passphrase");
        layout.addView(recoveryEnabled);
        LinearLayout recoveryFields = new LinearLayout(activity);
        recoveryFields.setOrientation(LinearLayout.VERTICAL);
        layout.addView(recoveryFields);
        EditText phrase = field(activity, recoveryFields, "Recovery passphrase (20+ characters, optional)", true);
        EditText repeatPhrase = field(activity, recoveryFields, "Repeat recovery passphrase", true);
        CheckBox saved = new CheckBox(activity);
        saved.setText("I recorded my recovery passphrase outside these devices and will export the encrypted backup.");
        recoveryFields.addView(saved);
        recoveryFields.setVisibility(View.GONE);
        recoveryEnabled.setOnCheckedChangeListener((button, checked) -> {
            recoveryFields.setVisibility(checked ? View.VISIBLE : View.GONE);
            if (!checked) { phrase.setText(""); repeatPhrase.setText(""); saved.setChecked(false); }
        });
        TextView validation = new TextView(activity);
        validation.setTextColor(android.graphics.Color.rgb(150, 20, 20));
        validation.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        layout.addView(validation);
        Map<String,EditText> inputs = new LinkedHashMap<>();
        inputs.put("username", username); inputs.put("hostname", hostname); inputs.put("timezone", zone);
        inputs.put("password", password); inputs.put("repeat_password", repeatPassword);
        inputs.put("disk", diskPassword); inputs.put("repeat_disk", repeatDisk);
        inputs.put("recovery", phrase); inputs.put("repeat_recovery", repeatPhrase);
        Button create = new Button(activity);
        create.setText("Create encrypted vault");
        create.setFilterTouchesWhenObscured(true);
        create.setOnClickListener(view -> {
            if (!active) return;
            try {
                Map<String,String> values = new LinkedHashMap<>();
                for (Map.Entry<String,EditText> input : inputs.entrySet()) {
                    input.getValue().setError(null);
                    values.put(input.getKey(), input.getValue().getText().toString());
                }
                saved.setError(null);
                Map<String,String> errors = EnrollmentValidation.errors(values, saved.isChecked(), recoveryEnabled.isChecked());
                values.clear();
                if (!errors.isEmpty()) {
                    validation.setText("Vault was not created. Fix these fields:\n\n" + String.join("\n", errors.values()));
                    for (Map.Entry<String,String> error : errors.entrySet()) {
                        if (error.getKey().equals("saved")) saved.setError(error.getValue());
                        else inputs.get(error.getKey()).setError(error.getValue());
                    }
                    String first = errors.keySet().iterator().next();
                    if (!first.equals("saved")) inputs.get(first).requestFocus();
                    return;
                }
                validation.setText("");
                String user = username.getText().toString();
                String host = hostname.getText().toString();
                String timezone = zone.getText().toString();
                String account = password.getText().toString();
                String recovery = phrase.getText().toString();
                String diskSecret = diskPassword.getText().toString();
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
            } catch (JSONException error) { validation.setText("Setup could not be prepared. No vault was changed. Please try again."); }
        });
        layout.addView(create);
    }
    static void add(JSONObject files, String name, JSONObject content) throws JSONException {
        files.put(name, android.util.Base64.encodeToString(content.toString().getBytes(StandardCharsets.UTF_8), android.util.Base64.NO_WRAP));
    }
    private EditText field(Activity activity, LinearLayout layout, String label, boolean secret) {
        TextView caption = new TextView(activity);
        caption.setText(label);
        layout.addView(caption);
        EditText field = new EditText(activity);
        field.setHint(label);
        field.setSingleLine(true);
        field.setInputType(InputType.TYPE_CLASS_TEXT | (secret ? InputType.TYPE_TEXT_VARIATION_PASSWORD : InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD));
        field.setSaveEnabled(false);
        field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        if (secret) {
            LinearLayout row = new LinearLayout(activity);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.addView(field, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1));
            Button visibility = new Button(activity);
            visibility.setText("Show");
            visibility.setContentDescription("Show " + label);
            visibility.setFilterTouchesWhenObscured(true);
            visibility.setOnClickListener(view -> {
                if (!active) return;
                boolean hidden = field.getTransformationMethod() instanceof android.text.method.PasswordTransformationMethod;
                int cursor = field.getSelectionStart();
                field.setTransformationMethod(hidden ? android.text.method.HideReturnsTransformationMethod.getInstance() :
                    android.text.method.PasswordTransformationMethod.getInstance());
                if (cursor >= 0) field.setSelection(Math.min(cursor, field.length()));
                visibility.setText(hidden ? "Hide" : "Show");
                visibility.setContentDescription((hidden ? "Hide " : "Show ") + label);
            });
            row.addView(visibility);
            layout.addView(row);
        } else layout.addView(field);
        fields.add(field);
        return field;
    }
    void clear() { active = false; for (EditText field : fields) field.setText(""); }
}
