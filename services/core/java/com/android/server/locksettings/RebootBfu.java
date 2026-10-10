package com.android.server.locksettings;

import android.util.Slog;

import com.android.server.power.PowerManagerService;

public class RebootBfu {
    static final String TAG = RebootBfu.class.getSimpleName();

    static void run() {
        Slog.d(TAG, "start");
        // No key destruction: a reboot drops all CE keys from memory and the next boot asks
        // for the credential again. init still kills processes, syncs and unmounts. No reason
        // string, so the boot reason looks like any other reboot.
        PowerManagerService.lowLevelReboot(null);
    }
}
