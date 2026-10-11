package com.android.server.locksettings;

import android.os.PowerManager;
import android.util.Slog;

import com.android.server.power.PowerManagerService;

public class RebootBfu {
    static final String TAG = RebootBfu.class.getSimpleName();

    static void run(LockSettingsService lockSettingsService) {
        Slog.d(TAG, "start");
        // A reboot escrow armed for a pending update would unlock the users again on the next
        // boot. Clear it first, a failure here must not stop the reboot.
        try {
            lockSettingsService.clearRebootEscrowForBfu();
        } catch (RuntimeException e) {
            Slog.e(TAG, "clearing reboot escrow failed", e);
        }
        // No key destruction: a reboot drops all CE keys from memory and the next boot asks
        // for the credential again. init still kills processes, syncs and unmounts. The reason
        // is the one the power menu passes, so the boot reason matches a user restart.
        // lowLevelReboot returns only if init didn't reboot within 20 s: ask again rather than
        // leave the device running after first unlock
        for (int attempt = 0; attempt < 3; attempt++) {
            PowerManagerService.lowLevelReboot(PowerManager.SHUTDOWN_USER_REQUESTED);
        }
        Slog.wtf(TAG, "device did not reboot");
    }
}
