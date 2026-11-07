package org.frankenstein.companion;

import org.junit.Test;
import static org.junit.Assert.*;
import java.util.*;

public class EnrollmentValidationTest {
    private Map<String,String> valid() {
        Map<String,String> values=new LinkedHashMap<>();
        values.put("username","fixture");values.put("hostname","githubtest");values.put("timezone","Asia/Jakarta");
        values.put("password","dummy-account-2026");values.put("repeat_password",values.get("password"));
        values.put("disk","dummy-disk-2026");values.put("repeat_disk",values.get("disk"));
        values.put("recovery","separate-dummy-recovery-2026");values.put("repeat_recovery",values.get("recovery"));
        return values;
    }
    @Test public void completeValidFormCanSubmit() {assertTrue(EnrollmentValidation.errors(valid(),true).isEmpty());}
    @Test public void eachRepeatPointsToItsOwnFieldWithoutEchoingSecrets() {
        Map<String,String> values=valid();
        for(String field:Arrays.asList("repeat_password","repeat_disk","repeat_recovery"))values.put(field,"private-mistyped-value");
        Map<String,String> errors=EnrollmentValidation.errors(values,true);
        assertEquals(new HashSet<>(Arrays.asList("repeat_password","repeat_disk","repeat_recovery")),errors.keySet());
        for(String error:errors.values())assertFalse(error.contains("private-mistyped-value"));
    }
    @Test public void shortRecoveryAndMissingAcknowledgmentHaveSeparateExplanations() {
        Map<String,String> values=valid();values.put("recovery","too-short");values.put("repeat_recovery","too-short");
        Map<String,String> errors=EnrollmentValidation.errors(values,false);
        assertEquals(new HashSet<>(Arrays.asList("recovery","saved")),errors.keySet());
        assertTrue(errors.get("recovery").contains("20"));assertTrue(errors.get("saved").contains("tick"));
    }
    @Test public void recoveryMustDifferFromBothMachinePasswords() {
        for(String field:Arrays.asList("password","disk")) {
            Map<String,String> values=valid();values.put(field,values.get("recovery"));
            values.put(field.equals("password")?"repeat_password":"repeat_disk",values.get(field));
            assertEquals(Collections.singleton("recovery"),EnrollmentValidation.errors(values,true).keySet());
        }
    }
    @Test public void profileErrorsIdentifyEachInvalidInput() {
        Map<String,String> values=valid();values.put("username","root");values.put("hostname","Invalid Host");values.put("timezone","Jakarta");
        assertEquals(new HashSet<>(Arrays.asList("username","hostname","timezone")),EnrollmentValidation.errors(values,true).keySet());
    }
    @Test public void passwordCharacterCountUsesCodePointsAndRejectsControlCharacters() {
        Map<String,String> values=valid();values.put("password","😀".repeat(6));values.put("repeat_password",values.get("password"));
        assertEquals(Collections.singleton("password"),EnrollmentValidation.errors(values,true).keySet());
        values.put("password","safe-looking\npassword");values.put("repeat_password",values.get("password"));
        assertEquals(Collections.singleton("password"),EnrollmentValidation.errors(values,true).keySet());
    }
}
