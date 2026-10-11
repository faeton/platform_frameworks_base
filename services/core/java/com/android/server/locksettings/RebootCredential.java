package com.android.server.locksettings;

import android.annotation.Nullable;
import android.os.UserHandle;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import libcore.util.HexEncoding;

import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PASSWORD;
import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PIN;

/**
 * Alternate owner credential that reboots the device when it's entered instead of a regular
 * credential. Stored next to the duress credentials, in the same format, under its own key.
 */
class RebootCredential {
    private static final String LOCK_SETTINGS_STORAGE_KEY = "reboot_credential";
    private static final int LOCK_SETTINGS_STORAGE_USER_ID = UserHandle.USER_SYSTEM;

    private static final int VERSION = 0;

    static void save(LockSettingsStorage lss, DuressCredential credential) {
        var bos = new ByteArrayOutputStream(500);
        var s = new DataOutputStream(bos);
        try {
            s.writeByte(VERSION);
            credential.serialize(s);
        } catch (IOException e) {
            // ByteArrayOutputStream never throws IOException
            throw new IllegalStateException(e);
        }
        lss.setString(LOCK_SETTINGS_STORAGE_KEY, HexEncoding.encodeToString(bos.toByteArray()),
                LOCK_SETTINGS_STORAGE_USER_ID);
    }

    /**
     * Returns the stored credential, or null when there is none. A record that can't be parsed
     * throws {@link IllegalStateException} with a fixed message, the record itself is never
     * logged.
     */
    @Nullable
    static DuressCredential maybeGet(LockSettingsStorage lss) {
        String str = lss.getString(LOCK_SETTINGS_STORAGE_KEY, null, LOCK_SETTINGS_STORAGE_USER_ID);
        if (str == null) {
            return null;
        }
        try {
            var s = new DataInputStream(new ByteArrayInputStream(HexEncoding.decode(str)));
            if (s.readUnsignedByte() != VERSION) {
                throw corrupt();
            }
            DuressCredential credential = DuressCredential.deserialize(s);
            int type = credential.getType();
            if (s.available() != 0
                    || (type != CREDENTIAL_TYPE_PIN && type != CREDENTIAL_TYPE_PASSWORD)) {
                throw corrupt();
            }
            return credential;
        } catch (IOException | RuntimeException e) {
            throw corrupt();
        }
    }

    private static IllegalStateException corrupt() {
        return new IllegalStateException("corrupt reboot credential record");
    }

    static void delete(LockSettingsStorage lss) {
        lss.removeKey(LOCK_SETTINGS_STORAGE_KEY, LOCK_SETTINGS_STORAGE_USER_ID);
    }
}
