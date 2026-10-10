package com.android.server.locksettings;

import android.annotation.Nullable;
import android.os.HandlerThread;
import android.os.UserHandle;
import android.util.Slog;

import com.android.internal.widget.LockscreenCredential;
import com.android.internal.widget.VerifyCredentialResponse;

import java.util.Objects;
import java.util.UUID;

import static com.android.internal.widget.LockDomain.Primary;
import static com.android.internal.widget.LockDomain.Secondary;
import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_NONE;
import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PASSWORD;
import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_PIN;

public class DuressPasswordHelper {
    static final String TAG = DuressPasswordHelper.class.getSimpleName();

    private final LockSettingsService lockSettingsService;
    private final LockSettingsStorage lockSettingsStorage;
    private final SyntheticPasswordManager spManager;
    private final HandlerThread backgroundThread;

    DuressPasswordHelper(LockSettingsService lockSettingsService,
            LockSettingsStorage lockSettingsStorage, SyntheticPasswordManager spManager) {
        var bgThread = new HandlerThread(UUID.randomUUID().toString());
        bgThread.start();
        this.backgroundThread = bgThread;
        this.lockSettingsService = lockSettingsService;
        this.lockSettingsStorage = lockSettingsStorage;
        this.spManager = spManager;
    }

    protected void onVerifyCredentialResult(@Nullable VerifyCredentialResponse res, @Nullable LockscreenCredential credential) {
        if (res != null && res.isMatched()) {
            return;
        }

        if (credential == null) {
            return;
        }

        // original credential is zeroized after this method returns
        LockscreenCredential credentialCopy = credential.duplicate();

        // credential verification is slow, don't block the current (usually binder) thread
        backgroundThread.getThreadHandler().post(() -> {
            final boolean isDuressCredential;
            boolean isRebootCredential = false;
            try {
                // duress is checked first, a reboot must never shadow a wipe
                isDuressCredential = isDuressCredential(credentialCopy);
                if (!isDuressCredential) {
                    isRebootCredential = isRebootCredential(credentialCopy);
                }
            } finally {
                // invalid credential might be similar to the actual credential
                credentialCopy.zeroize();
            }
            if (isDuressCredential) {
                DuressWipe.run(lockSettingsService.getContext());
            } else if (isRebootCredential) {
                RebootBfu.run();
            }
        });
    }

    private void checkOwnerCredential(LockscreenCredential ownerCredential) {
        int userId = UserHandle.USER_SYSTEM;

        if (lockSettingsService.getCredentialType(userId) == CREDENTIAL_TYPE_NONE) {
            if (!ownerCredential.isNone()) {
                throw new IllegalArgumentException("!ownerCredential.isNone()");
            }
        } else {
            VerifyCredentialResponse response = lockSettingsService.checkCredential(ownerCredential,
                    Primary, userId, null);

            if (!response.isMatched()) {
                throw new SecurityException("owner credential verification failed; " + response);
            }
        }
    }

    protected void setDuressCredentials(LockscreenCredential ownerCredential,
                                 LockscreenCredential pin, LockscreenCredential password) {
        Objects.requireNonNull(ownerCredential, "ownerCredential");
        Objects.requireNonNull(pin, "pin");
        Objects.requireNonNull(password, "password");

        checkOwnerCredential(ownerCredential);

        if (pin.isNone() && password.isNone()) {
            // exception handling is delegated to the caller
            DuressCredentials.delete(lockSettingsStorage);
            Slog.d(TAG, "deleted duress credentials");
            return;
        }

        DuressCredential.validate(pin, CREDENTIAL_TYPE_PIN);
        DuressCredential.validate(password, CREDENTIAL_TYPE_PASSWORD);

        DuressCredential rc = RebootCredential.maybeGet(lockSettingsStorage);
        if (rc != null) {
            LockscreenCredential sameType = rc.getType() == CREDENTIAL_TYPE_PIN ? pin : password;
            if (rc.verify(spManager, sameType)) {
                throw new IllegalArgumentException(COLLISION_REBOOT);
            }
        }

        // exception handling is delegated to the caller
        DuressCredentials.create(spManager, pin, password).save(lockSettingsStorage);
    }

    protected boolean hasDuressCredentials(LockscreenCredential ownerCredential) {
        checkOwnerCredential(ownerCredential);
        return DuressCredentials.maybeGet(lockSettingsStorage) != null;
    }

    static final String COLLISION_OWNER = "collision: owner credential";
    static final String COLLISION_SECOND_FACTOR = "collision: owner second factor";
    static final String COLLISION_DURESS = "collision: duress credential";
    static final String COLLISION_REBOOT = "collision: reboot credential";

    /**
     * Sets the owner's reboot credential, or deletes it when {@code credential} is none.
     * {@code ownerSecondFactor} is required when the owner has a second-factor PIN, so that the
     * candidate can be compared with it in memory instead of being probed through a verifier.
     */
    protected void setRebootCredential(LockscreenCredential ownerCredential,
            LockscreenCredential ownerSecondFactor, LockscreenCredential credential) {
        Objects.requireNonNull(ownerCredential, "ownerCredential");
        Objects.requireNonNull(ownerSecondFactor, "ownerSecondFactor");
        Objects.requireNonNull(credential, "credential");

        int userId = UserHandle.USER_SYSTEM;
        boolean hasSecondFactor =
                lockSettingsService.getCredentialType(userId, Secondary) != CREDENTIAL_TYPE_NONE;

        // compare before the owner checks, which zeroize parceled credentials
        boolean sameAsOwner = credential.equals(ownerCredential);
        boolean sameAsSecondFactor = hasSecondFactor && credential.equals(ownerSecondFactor);

        checkOwnerCredential(ownerCredential);

        if (credential.isNone()) {
            RebootCredential.delete(lockSettingsStorage);
            Slog.d(TAG, "deleted reboot credential");
            return;
        }

        if (lockSettingsService.getCredentialType(userId) == CREDENTIAL_TYPE_NONE) {
            throw new IllegalStateException("owner has no screen lock");
        }

        if (hasSecondFactor) {
            VerifyCredentialResponse response = lockSettingsService.checkCredential(
                    ownerSecondFactor, Secondary, userId, null);
            if (!response.isMatched()) {
                throw new SecurityException("owner second factor verification failed; "
                        + response);
            }
        }

        int type = credential.getType();
        if (type != CREDENTIAL_TYPE_PIN && type != CREDENTIAL_TYPE_PASSWORD) {
            throw new IllegalArgumentException("unsupported credential type " + type);
        }
        DuressCredential.validate(credential, type);

        if (sameAsOwner) {
            throw new IllegalArgumentException(COLLISION_OWNER);
        }
        if (sameAsSecondFactor) {
            throw new IllegalArgumentException(COLLISION_SECOND_FACTOR);
        }
        DuressCredentials dc = DuressCredentials.maybeGet(lockSettingsStorage);
        if (dc != null && dc.get(type).verify(spManager, credential)) {
            throw new IllegalArgumentException(COLLISION_DURESS);
        }

        RebootCredential.save(lockSettingsStorage, DuressCredential.create(credential, spManager));
    }

    protected boolean hasRebootCredential(LockscreenCredential ownerCredential) {
        checkOwnerCredential(ownerCredential);
        return RebootCredential.maybeGet(lockSettingsStorage) != null;
    }

    private boolean isRebootCredential(LockscreenCredential credential) {
        DuressCredential rc = RebootCredential.maybeGet(lockSettingsStorage);
        return rc != null && rc.getType() == credential.getType()
                && rc.verify(spManager, credential);
    }

    private boolean isDuressCredential(LockscreenCredential credential) {
        int credentialType = credential.getType();
        switch (credentialType) {
            case CREDENTIAL_TYPE_PIN:
            case CREDENTIAL_TYPE_PASSWORD:
                DuressCredentials dc = DuressCredentials.maybeGet(lockSettingsStorage);
                return dc != null && dc.get(credentialType).verify(spManager, credential);
            default:
                return false;
        }
    }
}
