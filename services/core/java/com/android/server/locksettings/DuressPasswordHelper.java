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
import java.util.Set;
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

    // Changes of the owner's credential or of who the owner is. A call that checked the owner's
    // credential is refused if this moved before it reads or writes the alternates.
    @GuardedBy("alternatesLock")
    private int ownerCredentialChanges;

    static final String OWNER_CREDENTIAL_CHANGED = "owner credential changed, try again";
    static final String NOT_AUTHORITY = "not the alternates authority";

    // The user whose credential manages the alternate credentials ("owner" below). User 0
    // unless the device is set up with a protected space, which then holds them. The serial
    // number guards against a removed user's id being reused.
    private static final String AUTHORITY_KEY = "alternates_authority_user";
    private static final String AUTHORITY_SERIAL_KEY = "alternates_authority_serial";

    /** Records only this class may read or write, never through the generic key calls. */
    static final Set<String> RESERVED_KEYS = Set.of(AUTHORITY_KEY, AUTHORITY_SERIAL_KEY,
            DuressCredentials.LOCK_SETTINGS_STORAGE_KEY, RebootCredential.LOCK_SETTINGS_STORAGE_KEY,
            LockSettingsService.LAYOUT_PIN_LENGTH_KEY);

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
     * Called before a credential of {@code userId} is changed, so that an enrolment whose owner
     * checks ran before the change is refused even if it saves before the change completes.
     * May be called with the SyntheticPasswordManager lock held: only counts.
     */
    protected void onLockCredentialChanging(int userId) {
        synchronized (alternatesLock) {
            if (userId == authorityLocked()) {
                ownerCredentialChanges++;
            }
        }
    }

    /**
     * Called after a credential of {@code userId} has changed. The reboot credential is deleted
     * when the owner removes the screen lock or picks a credential equal to it: in both cases it
     * would no longer do what it was enrolled for.
     */
    protected void onLockCredentialChanged(LockscreenCredential newCredential,
            LockDomain lockDomain, int userId) {
        synchronized (alternatesLock) {
            if (userId != authorityLocked()) {
                return;
            }
            ownerCredentialChanges++;
            // the change is already committed: never fail it from here
            try {
                if (newCredential.isNone()) {
                    // deleting doesn't parse, so a corrupt record goes as well. A cleared second
                    // factor (also called with the SyntheticPasswordManager lock held) does
                    // nothing here
                    if (lockDomain == Primary && RebootCredential.exists(lockSettingsStorage)) {
                        RebootCredential.delete(lockSettingsStorage);
                        Slog.i(TAG, "deleted reboot credential, owner screen lock removed");
                    }
                    return;
                }
                DuressCredential rc = RebootCredential.maybeGet(lockSettingsStorage);
                if (rc != null && rc.getType() == newCredential.getType()
                        && rc.verify(spManager, newCredential)) {
                    RebootCredential.delete(lockSettingsStorage);
                    Slog.i(TAG, "deleted reboot credential, equal to the new owner credential");
                }
            } catch (RuntimeException e) {
                Slog.e(TAG, "reboot credential check after a change failed: "
                        + e.getClass().getSimpleName());
            }
        }
    }

    /** The user whose own credential manages the alternate credentials. */
    public int getAuthorityUserId() {
        synchronized (alternatesLock) {
            return authorityLocked();
        }
    }

    @GuardedBy("alternatesLock")
    private int authorityLocked() {
        return lockSettingsStorage.getInt(AUTHORITY_KEY, UserHandle.USER_SYSTEM,
                UserHandle.USER_SYSTEM);
    }

    /**
     * Makes {@code userId}, whose serial number is {@code serialNumber}, the user that manages
     * the alternate credentials. The reboot credential was enrolled against the previous one's
     * credential and is deleted; the duress credentials are device-wide and stay.
     */
    void setAuthority(int userId, int serialNumber) {
        synchronized (alternatesLock) {
            setAuthorityLocked(userId, serialNumber);
        }
    }

    @GuardedBy("alternatesLock")
    private void setAuthorityLocked(int userId, int serialNumber) {
        if (userId == authorityLocked() && (userId == UserHandle.USER_SYSTEM || serialNumber
                == lockSettingsStorage.getInt(AUTHORITY_SERIAL_KEY, -1, UserHandle.USER_SYSTEM))) {
            return;
        }
        ownerCredentialChanges++;
        RebootCredential.delete(lockSettingsStorage);
        if (userId == UserHandle.USER_SYSTEM) {
            lockSettingsStorage.removeKey(AUTHORITY_KEY, UserHandle.USER_SYSTEM);
            lockSettingsStorage.removeKey(AUTHORITY_SERIAL_KEY, UserHandle.USER_SYSTEM);
        } else {
            lockSettingsStorage.setInt(AUTHORITY_SERIAL_KEY, serialNumber, UserHandle.USER_SYSTEM);
            lockSettingsStorage.setInt(AUTHORITY_KEY, userId, UserHandle.USER_SYSTEM);
        }
        Slog.i(TAG, "alternates authority is now user " + userId);
    }

    /** A removed authority hands the alternates back to user 0. */
    void onUserRemoved(int userId) {
        synchronized (alternatesLock) {
            if (userId == authorityLocked()) {
                setAuthorityLocked(UserHandle.USER_SYSTEM, 0);
            }
        }
    }

    /**
     * Drops an authority whose user is gone or whose id now belongs to another user, for removals
     * that never reached {@link #onUserRemoved}. {@code currentSerialNumber} is the serial number
     * of the user that now has the stored id, or -1 if there is none.
     */
    void dropStaleAuthority(int userId, int currentSerialNumber) {
        synchronized (alternatesLock) {
            if (userId == UserHandle.USER_SYSTEM || userId != authorityLocked()) {
                return;
            }
            int stored = lockSettingsStorage.getInt(AUTHORITY_SERIAL_KEY, -1,
                    UserHandle.USER_SYSTEM);
            if (currentSerialNumber != stored) {
                Slog.w(TAG, "alternates authority user " + userId + " is gone");
                setAuthorityLocked(UserHandle.USER_SYSTEM, 0);
            }
        }
    }

    /**
     * Checks that {@code userId} is the authority and returns the change count to pass to
     * {@link #checkUnchangedLocked} once its credential has been checked.
     */
    private int checkAuthority(int userId) {
        synchronized (alternatesLock) {
            if (userId != authorityLocked()) {
                throw new SecurityException(NOT_AUTHORITY);
            }
            return ownerCredentialChanges;
        }
    }

    // credential checks run outside alternatesLock (they may take the SyntheticPasswordManager
    // lock), so the authority or its credential may have changed since
    @GuardedBy("alternatesLock")
    private void checkUnchangedLocked(int userId, int changesBefore) {
        if (ownerCredentialChanges != changesBefore) {
            throw new IllegalStateException(OWNER_CREDENTIAL_CHANGED);
        }
        if (userId != authorityLocked()) {
            throw new SecurityException(NOT_AUTHORITY);
        }
    }

    private void checkOwnerCredential(LockscreenCredential ownerCredential, int userId) {

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
            LockscreenCredential pin, LockscreenCredential password, int userId) {
        Objects.requireNonNull(ownerCredential, "ownerCredential");
        Objects.requireNonNull(pin, "pin");
        Objects.requireNonNull(password, "password");

        int changesBefore = checkAuthority(userId);
        checkOwnerCredential(ownerCredential, userId);

        if (pin.isNone() && password.isNone()) {
            synchronized (alternatesLock) {
                checkUnchangedLocked(userId, changesBefore);
                // exception handling is delegated to the caller
                DuressCredentials.delete(lockSettingsStorage);
            }
            Slog.d(TAG, "deleted duress credentials");
            return;
        }

        DuressCredential.validate(pin, CREDENTIAL_TYPE_PIN);
        DuressCredential.validate(password, CREDENTIAL_TYPE_PASSWORD);
        lockSettingsService.checkLayoutPinLength(pin);
        lockSettingsService.checkAlternateAgainstOwner(pin);

        synchronized (alternatesLock) {
            checkUnchangedLocked(userId, changesBefore);
            DuressCredential rc;
            try {
                rc = RebootCredential.maybeGet(lockSettingsStorage);
            } catch (IllegalStateException e) {
                // an unreadable reboot record can't collide and mustn't block duress enrolment
                Slog.e(TAG, e.getMessage());
                rc = null;
            }
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

    protected boolean hasDuressCredentials(LockscreenCredential ownerCredential, int userId) {
        int changesBefore = checkAuthority(userId);
        checkOwnerCredential(ownerCredential, userId);
        synchronized (alternatesLock) {
            checkUnchangedLocked(userId, changesBefore);
            return DuressCredentials.maybeGet(lockSettingsStorage) != null;
        }
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
            LockscreenCredential ownerSecondFactor, LockscreenCredential credential, int userId) {
        Objects.requireNonNull(ownerCredential, "ownerCredential");
        Objects.requireNonNull(ownerSecondFactor, "ownerSecondFactor");
        Objects.requireNonNull(credential, "credential");

        // sampled before the owner checks: a change after them would make the checks stale
        int changesBefore = checkAuthority(userId);
        boolean hasSecondFactor =
                lockSettingsService.getCredentialType(userId, Secondary) != CREDENTIAL_TYPE_NONE;

        // compare before the owner checks, which zeroize parceled credentials
        boolean sameAsOwner = credential.equals(ownerCredential);
        boolean sameAsSecondFactor = hasSecondFactor && credential.equals(ownerSecondFactor);

        checkOwnerCredential(ownerCredential, userId);

        if (credential.isNone()) {
            // deleting never parses the record, so a corrupt one can always be removed
            synchronized (alternatesLock) {
                checkUnchangedLocked(userId, changesBefore);
                RebootCredential.delete(lockSettingsStorage);
            }
            Slog.d(TAG, "deleted reboot credential");
            return;
        }

        if (lockSettingsService.getCredentialType(userId) == CREDENTIAL_TYPE_NONE) {
            throw new IllegalStateException("owner has no screen lock");
        }

        if (hasSecondFactor) {
            if (ownerSecondFactor.isNone()) {
                throw new SecurityException("owner second factor required");
            }
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
        lockSettingsService.checkLayoutPinLength(credential);
        // with a protected space the lock screen is a PIN pad, so a password couldn't be typed
        if (type == CREDENTIAL_TYPE_PASSWORD && getAuthorityUserId() != UserHandle.USER_SYSTEM) {
            throw new IllegalArgumentException("the reboot credential must be a PIN");
        }
        lockSettingsService.checkAlternateAgainstOwner(credential);

        if (sameAsOwner) {
            throw new IllegalArgumentException(COLLISION_OWNER);
        }
        if (sameAsSecondFactor) {
            throw new IllegalArgumentException(COLLISION_SECOND_FACTOR);
        }
        afterOwnerChecks();
        // the owner checks above verify through doVerifyCredential and may take the
        // SyntheticPasswordManager lock, so they stay outside alternatesLock
        synchronized (alternatesLock) {
            checkUnchangedLocked(userId, changesBefore);
            DuressCredentials dc = DuressCredentials.maybeGet(lockSettingsStorage);
            if (dc != null && dc.get(type).verify(spManager, credential)) {
                throw new IllegalArgumentException(COLLISION_DURESS);
            }

            RebootCredential.save(lockSettingsStorage,
                    DuressCredential.create(credential, spManager));
        }
    }

    /** Between the owner checks of an enrolment and its save. Tests change the owner here. */
    @VisibleForTesting
    void afterOwnerChecks() {
    }

    protected boolean hasRebootCredential(LockscreenCredential ownerCredential, int userId) {
        int changesBefore = checkAuthority(userId);
        checkOwnerCredential(ownerCredential, userId);
        synchronized (alternatesLock) {
            checkUnchangedLocked(userId, changesBefore);
            return RebootCredential.maybeGet(lockSettingsStorage) != null;
        }
    }

    /** True for the duress PIN or password and for the reboot credential. */
    protected boolean isAlternateCredential(LockscreenCredential credential) {
        synchronized (alternatesLock) {
            boolean duress;
            try {
                duress = isDuressCredential(credential);
            } catch (IllegalStateException e) {
                // an unreadable record can't collide and mustn't block a PIN change
                Slog.e(TAG, e.getMessage());
                duress = false;
            }
            if (duress) {
                return true;
            }
            try {
                return isRebootCredential(credential);
            } catch (IllegalStateException e) {
                Slog.e(TAG, e.getMessage());
                return false;
            }
        }
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
