package com.android.server;

import android.content.ContentResolver;
import android.content.Context;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Handler;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.provider.Settings;

/**
 * Tells the boot animation that the owner's first setup is done: it shows our logo until then
 * and the plain Android one after.
 */
public final class BootLogoSetupFlag {
    private static final String PROP = "persist.sys.bootanim.setup_done";

    private BootLogoSetupFlag() {}

    public static void start(Context context, Handler handler) {
        if (SystemProperties.getBoolean(PROP, false)) {
            return;
        }
        final ContentResolver resolver = context.getContentResolver();
        final Uri uri = Settings.Secure.getUriFor(Settings.Secure.USER_SETUP_COMPLETE);
        final ContentObserver observer = new ContentObserver(handler) {
            @Override
            public void onChange(boolean selfChange) {
                if (check(resolver)) {
                    resolver.unregisterContentObserver(this);
                }
            }
        };
        resolver.registerContentObserver(uri, false, observer, UserHandle.USER_SYSTEM);
        // checked after registering, so a change in between isn't missed
        if (check(resolver)) {
            resolver.unregisterContentObserver(observer);
        }
    }

    private static boolean check(ContentResolver resolver) {
        if (Settings.Secure.getIntForUser(resolver, Settings.Secure.USER_SETUP_COMPLETE, 0,
                UserHandle.USER_SYSTEM) == 0) {
            return false;
        }
        SystemProperties.set(PROP, "true");
        return true;
    }
}
