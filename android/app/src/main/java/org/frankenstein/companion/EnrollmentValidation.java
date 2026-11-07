package org.frankenstein.companion;

import java.util.*;

/** Field-specific validation. Errors never contain submitted secret values. */
final class EnrollmentValidation {
    static Map<String,String> errors(Map<String,String> values, boolean saved) {
        Map<String,String> errors = new LinkedHashMap<>();
        String user = values.get("username"), host = values.get("hostname"), zone = values.get("timezone");
        String account = values.get("password"), disk = values.get("disk"), recovery = values.get("recovery");
        if (!user.matches("[a-z][a-z0-9_-]{0,30}") || user.equals("root"))
            errors.put("username", "Use 1–31 lowercase letters, numbers, _ or -. Start with a letter; root is reserved.");
        if (!host.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"))
            errors.put("hostname", "Use 1–63 lowercase letters, numbers or -. Start and end with a letter or number.");
        if (!Arrays.asList(TimeZone.getAvailableIDs()).contains(zone))
            errors.put("timezone", "Choose a valid timezone, for example Asia/Jakarta or UTC.");
        if (!secret(account,12)) errors.put("password", "Account password needs at least 12 characters, with no line breaks.");
        if (!account.equals(values.get("repeat_password"))) errors.put("repeat_password", "Repeat the account password exactly.");
        if (!secret(disk,12)) errors.put("disk", "Disk passphrase needs at least 12 characters, with no line breaks.");
        if (!disk.equals(values.get("repeat_disk"))) errors.put("repeat_disk", "Repeat the disk passphrase exactly.");
        if (!secret(recovery,20)) errors.put("recovery", "Recovery passphrase needs at least 20 characters, with no line breaks.");
        else if (recovery.equals(account) || recovery.equals(disk))
            errors.put("recovery", "Use a recovery passphrase different from both account and disk passwords.");
        if (!recovery.equals(values.get("repeat_recovery"))) errors.put("repeat_recovery", "Repeat the recovery passphrase exactly.");
        if (!saved) errors.put("saved", "Record the recovery passphrase separately, then tick the confirmation box.");
        return errors;
    }
    private static boolean secret(String value, int minimum) {
        return value.codePointCount(0,value.length()) >= minimum && value.length() <= 4096 &&
            value.indexOf('\n')<0 && value.indexOf('\r')<0 && value.indexOf('\0')<0;
    }
}
