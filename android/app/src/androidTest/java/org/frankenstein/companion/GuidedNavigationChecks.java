package org.frankenstein.companion;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import java.util.*;

/** Navigation only: never accepts device approval, PIN, login, export or upload. */
final class GuidedNavigationChecks {
    private static void buttons(View view, Map<String,Button> result) {
        if (view instanceof Button) result.put(((Button)view).getText().toString(), (Button)view);
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup)view;
            for (int i=0;i<group.getChildCount();i++) buttons(group.getChildAt(i), result);
        }
    }
    private static Map<String,Button> expect(Activity activity, String... expected) {
        Map<String,Button> found = new HashMap<>();
        buttons(activity.getWindow().getDecorView(), found);
        if (!found.keySet().equals(new HashSet<>(Arrays.asList(expected))))
            throw new AssertionError("Unrelated actions visible in guided step: " + found.keySet());
        return found;
    }
    static void run(Instrumentation test) throws Exception {
        Activity activity = test.startActivitySync(new Intent(test.getTargetContext(), MainActivity.class)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK));
        boolean populated = !new NativeVault(test.getTargetContext()).current().equals(NativeVault.EMPTY);
        test.runOnMainSync(() -> {
            try {
                if (populated) {
                    expect(activity, "Encrypted backup", "Open my vault").get("Encrypted backup").performClick();
                    expect(activity, "GitHub private repository", "Save a ZIP file", "Back").get("Save a ZIP file").performClick();
                    expect(activity, "Next: choose save location", "Back").get("Back").performClick();
                    expect(activity, "GitHub private repository", "Save a ZIP file", "Back");
                } else {
                    expect(activity, "Receive from my PC", "Set up on this phone").get("Receive from my PC").performClick();
                    expect(activity, "Back").get("Back").performClick();
                    expect(activity, "Receive from my PC", "Set up on this phone");
                }
            } finally { activity.finish(); }
        });
    }
}
