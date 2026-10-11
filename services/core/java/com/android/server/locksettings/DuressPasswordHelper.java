package com.android.server.locksettings;

import android.annotation.Nullable;
import android.os.HandlerThread;
import android.os.UserHandle;
import android.util.Slog;
import android.util.SparseIntArray;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;
import com.android.internal.widget.LockDomain;
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
    private final Actions actions;

    // collision checks of the alternate credentials and their writes
    private final Object alternatesLock = new Object();

    // successful verifications per user, a queued reboot is dropped when this changes
    @GuardedBy("verifiedCount")
    private final SparseIntArray verifiedCount = new SparseIntArray();

    /** What the alternate credentials do. Tests replace these. */
    @VisibleForTesting
    interface Actions {
        void wipe();
        void reboot();
    }

    DuressPasswordHelper(LockSettingsService lockSettingsService,
            LockSettingsStorage lockSettingsStorage, SyntheticPasswordManager spManager) {
        this(lockSettingsService, lockSettingsStorage, spManager, new Actions() {
            @Override
            public void wipe() {
                DuressWipe.run(lockSettingsService.getContext());
            }

            @Override
            public void reboot() {
                RebootBfu.run(lockSettingsService);
            }
        });
    }

    @VisibleForTesting
    DuressPasswordHelper(LockSettingsService lockSettingsService,
            LockSettingsStorage lockSettingsStorage, SyntheticPasswordManager spManager,
            Actions actions) {
        var bgThread = new HandlerThread(UUID.randomUUID().toString());
        bgThread.start();
        this.backgroundThread = bgThread;
        this.lockSettingsService = lockSettingsService;
        this.lockSettingsStorage = lockSettingsStorage;
        this.spManager = spManager;
        this.actions = actions;
    }

    @VisibleForTesting
    HandlerThread getBackgroundThread() {
        return backgroundThread;
    }

    private int getVerifiedCount(int userId) {
        synchronized (verifiedCount) {
            return verifiedCount.get(userId);
        }
    }

    protected void onVerifyCredentialResult(@Nullable VerifyCredentialResponse res,
            @Nullable LockscreenCredential credential, int userId) {
        if (res != null && res.isMatched()) {
            synchronized (verifiedCount) {
                verifiedCount.put(userId, verifiedCount.get(userId) + 1);
            }
            return;
        }

        if (credential == null) {
            return;
        }

        // original credential is zeroized after this method returns
        LockscreenCredential credentialCopy = credential.duplicate();
        int verifiedBefore = getVerifiedCount(userId);

        // credential verification is slow, don't block the current (usually binder) thread
        backgroundThread.getThreadHandler().post(() -> {
            boolean isDuressCredential = false;
            boolean isRebootCredential = false;
            try {
                // duress is checked first, a reboot must never shadow a wipe. A record that
                // can't be read only disables its own action. The exceptions can carry the
                // stored record, so only their type is logged.
                try {
                    isDuressCredential = isDuressCredential(credentialCopy);
                } catch (RuntimeException e) {
                    Slog.e(TAG, "duress check failed: " + e.getClass().getSimpleName());
                }
                if (!isDuressCredential) {
                    try {
                        isRebootCredential = isRebootCredential(credentialCopy);
                    } catch (RuntimeException e) {
                        Slog.e(TAG, "reboot check failed: " + e.getClass().getSimpleName());
                    }
                }
            } finally {
                // invalid credential might be similar to the actual credential
                credentialCopy.zeroize();
            }
            if (isDuressCredential) {
                actions.wipe();
            } else if (isRebootCredential) {
                // the real credential was entered while this attempt was queued
                if (getVerifiedCount(userId) != verifiedBefore) {
                    Slog.i(TAG, "reboot dropped, user " + userId + " verified meanwhile");
                    return;
                }
                actions.reboot();
            }
        });
    }

    /**
     * Called after a credential of {@code userId} has changed. The reboot credential is deleted
     * when the owner removes the screen lock or picks a credential equal to it: in both cases it
     * would no longer do what it was enrolled for.
     */
    protected void onLockCredentialChanged(LockscreenCredential newCredential,
            LockDomain lockDomain, int userId) {
        if (userId != UserHandle.USER_SYSTEM) {
            return;
        }
        synchronized (alternatesLock) {
            DuressCredential rc;
            try {
                rc = RebootCredential.maybeGet(lockSettingsStorage);
            } catch (IllegalStateException e) {
                Slog.e(TAG, e.getMessage());
                return;
            }
            if (rc == null) {
                return;
            }
            String reason = null;
            if (newCredential.isNone()) {
                if (lockDomain == Primary) {
                    reason = "owner screen lock removed";
                }
            } else if (rc.getType() == newCredential.getType()
                    && rc.verify(spManager, newCredential)) {
                reason = "equal to the new owner credential";
            }
            if (reason != null) {
                RebootCredential.delete(lockSettingsStorage);
                Slog.i(TAG, "deleted reboot credential, " + reason);
            }
        }
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

        synchronized (alternatesLock) {
            DuressCredential rc = RebootCredential.maybeGet(lockSettingsStorage);
            if (rc != null) {
                LockscreenCredential sameType =
                        rc.getType() == CREDENTIAL_TYPE_PIN ? pin : password;
                if (rc.verify(spManager, sameType)) {
                    throw new IllegalArgumentException(COLLISION_REBOOT);
                }
            }

            // exception handling is delegated to the caller
            DuressCredentials.create(spManager, pin, password).save(lockSettingsStorage);
        }
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
            // deleting never parses the record, so a corrupt one can always be removed
            synchronized (alternatesLock) {
                RebootCredential.delete(lockSettingsStorage);
            }
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
        // the owner checks above verify through doVerifyCredential and may take the
        // SyntheticPasswordManager lock, so they stay outside alternatesLock
        synchronized (alternatesLock) {
            DuressCredentials dc = DuressCredentials.maybeGet(lockSettingsStorage);
            if (dc != null && dc.get(type).verify(spManager, credential)) {
                throw new IllegalArgumentException(COLLISION_DURESS);
            }

            RebootCredential.save(lockSettingsStorage,
                    DuressCredential.create(credential, spManager));
        }
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
