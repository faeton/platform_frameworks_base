package com.android.server.locksettings;

import android.annotation.Nullable;
import android.os.UserHandle;

import com.android.server.locksettings.SyntheticPasswordManager.PasswordData;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import libcore.util.HexEncoding;

import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PASSWORD;
import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PIN;
import static com.android.internal.widget.LockPatternUtils.PIN_LENGTH_UNAVAILABLE;

/**
 * Alternate owner credential that reboots the device when it's entered instead of a regular
 * credential. Stored next to the duress credentials, in the same format, under its own key.
 */
class RebootCredential {
    static final String LOCK_SETTINGS_STORAGE_KEY = "reboot_credential";
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
        if (str.length() != 2 * RECORD_LENGTH) {
            throw corrupt();
        }
        try {
            return parse(HexEncoding.decode(str));
        } catch (IOException | RuntimeException e) {
            throw corrupt();
        }
    }

    // A valid record is always the same size, checked before decoding: version, PasswordData
    // length + PasswordData (type, 3 exponents, salt length + salt, handle length, PIN length),
    // hash length + hash. Only the parameters this device writes are accepted, so a damaged
    // record can't make the check allocate or stretch more than an enrolled one.
    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;  // SyntheticPasswordManager.STRETCHED_LSKF_LENGTH
    private static final int PASSWORD_DATA_LENGTH = 4 + 3 + 4 + SALT_LENGTH + 4 + 4;
    private static final int RECORD_LENGTH = 1 + 4 + PASSWORD_DATA_LENGTH + 4 + HASH_LENGTH;

    private static DuressCredential parse(byte[] record) throws IOException {
        var s = new DataInputStream(new ByteArrayInputStream(record));
        if (s.readUnsignedByte() != VERSION) {
            throw corrupt();
        }
        if (s.readInt() != PASSWORD_DATA_LENGTH) {
            throw corrupt();
        }
        byte[] passwordData = s.readNBytes(PASSWORD_DATA_LENGTH);
        if (s.readInt() != HASH_LENGTH || s.available() != HASH_LENGTH) {
            throw corrupt();
        }
        byte[] hash = s.readNBytes(HASH_LENGTH);

        // layout of PasswordData.toBytes(): type, 3 scrypt exponents, salt, handle, PIN length
        var b = ByteBuffer.wrap(passwordData);
        int type = b.getInt();
        if (type != CREDENTIAL_TYPE_PIN && type != CREDENTIAL_TYPE_PASSWORD) {
            throw corrupt();
        }
        b.position(b.position() + 3);
        if (b.getInt() != SALT_LENGTH) {
            throw corrupt();
        }
        b.position(b.position() + SALT_LENGTH);
        if (b.getInt() != 0) {
            throw corrupt();
        }
        PasswordData salt = PasswordData.fromBytes(passwordData);
        PasswordData expected = PasswordData.create(type, PIN_LENGTH_UNAVAILABLE);
        if (salt.scryptLogN != expected.scryptLogN || salt.scryptLogR != expected.scryptLogR
                || salt.scryptLogP != expected.scryptLogP
                || salt.pinLength != PIN_LENGTH_UNAVAILABLE) {
            throw corrupt();
        }
        return new DuressCredential(salt, hash);
    }

    private static IllegalStateException corrupt() {
        return new IllegalStateException("corrupt reboot credential record");
    }

    static boolean exists(LockSettingsStorage lss) {
        String str = lss.getString(LOCK_SETTINGS_STORAGE_KEY, null, LOCK_SETTINGS_STORAGE_USER_ID);
        return str != null;
    }

    static void delete(LockSettingsStorage lss) {
        lss.removeKey(LOCK_SETTINGS_STORAGE_KEY, LOCK_SETTINGS_STORAGE_USER_ID);
    }
}
