package com.android.server.locksettings;

import static com.android.internal.widget.LockDomain.Primary;
import static com.android.internal.widget.LockDomain.Secondary;
import static com.android.internal.widget.LockPatternUtils.CREDENTIAL_TYPE_NONE;

import static com.google.common.truth.Truth.assertThat;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.platform.test.annotations.Presubmit;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.internal.widget.LockscreenCredential;
import com.android.internal.widget.VerifyCredentialResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;

/** Duress and reboot credentials, with the real helper and actions that only count calls. */
@SmallTest
@Presubmit
@RunWith(AndroidJUnit4.class)
public class AlternateCredentialsTests extends BaseLockSettingsServiceTests {
    private static final String OWNER = "111100";
    private static final String DURESS_PIN = "999900";
    private static final String DURESS_PASSWORD = "duress-pw";
    private static final String REBOOT = "555500";

    private int mWipes;
    private int mReboots;
    private DuressPasswordHelper mHelper;

    @Before
    public void setUpHelper() {
        mHelper = new DuressPasswordHelper(mService, mStorage, mSpManager,
                new DuressPasswordHelper.Actions() {
                    @Override
                    public void wipe() {
                        mWipes++;
                    }

                    @Override
                    public void reboot() {
                        mReboots++;
                    }
                });
        mService.initializeSyntheticPassword(PRIMARY_USER_ID);
        assertTrue(mService.setLockCredential(newPin(OWNER), nonePassword(), PRIMARY_USER_ID));
    }

    private void setReboot(String pin) {
        mHelper.setRebootCredential(newPin(OWNER), nonePassword(), newPin(pin), PRIMARY_USER_ID);
    }

    private void setDuress(String pin, String password) {
        mHelper.setDuressCredentials(newPin(OWNER), newPin(pin), newPassword(password),
                PRIMARY_USER_ID);
    }

    private void enter(LockscreenCredential credential, int userId) {
        mHelper.onVerifyCredentialResult(VerifyCredentialResponse.credIncorrect(), credential,
                userId);
        flushHelper();
    }

    private void flushHelper() {
        mHelper.getBackgroundThread().getThreadHandler().runWithScissors(() -> { }, 0);
    }

    private static void assertCollision(String message, Runnable r) {
        var e = assertThrows(IllegalArgumentException.class, r::run);
        assertThat(e).hasMessageThat().isEqualTo(message);
    }

    @Test
    public void rebootCredential_firesAtEveryUsersPrompt() {
        setReboot(REBOOT);
        assertThat(mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID)).isTrue();

        enter(newPin(REBOOT), PRIMARY_USER_ID);
        enter(newPin(REBOOT), SECONDARY_USER_ID);

        assertThat(mReboots).isEqualTo(2);
        assertThat(mWipes).isEqualTo(0);
    }

    @Test
    public void rebootCredential_otherCredentialsDoNothing() {
        setReboot(REBOOT);

        enter(newPin("000000"), PRIMARY_USER_ID);
        // same digits as a password: matching is type-specific
        enter(newPassword(REBOOT), PRIMARY_USER_ID);
        // a matching credential never reaches the background check
        mHelper.onVerifyCredentialResult(VerifyCredentialResponse.OK, newPin(REBOOT),
                PRIMARY_USER_ID);
        flushHelper();

        assertThat(mReboots).isEqualTo(0);
    }

    @Test
    public void rebootCredential_password() {
        mHelper.setRebootCredential(newPin(OWNER), nonePassword(), newPassword("reboot-pw"), PRIMARY_USER_ID);

        enter(newPassword("reboot-pw"), PRIMARY_USER_ID);

        assertThat(mReboots).isEqualTo(1);
    }

    @Test
    public void duressIsCheckedFirst() {
        setReboot(REBOOT);
        setDuress(DURESS_PIN, DURESS_PASSWORD);

        enter(newPin(DURESS_PIN), PRIMARY_USER_ID);

        assertThat(mWipes).isEqualTo(1);
        assertThat(mReboots).isEqualTo(0);
    }

    @Test
    public void queuedReboot_droppedAfterSuccessfulVerify() throws Exception {
        setReboot(REBOOT);
        var hold = new CountDownLatch(1);
        mHelper.getBackgroundThread().getThreadHandler().post(() -> {
            try {
                hold.await();
            } catch (InterruptedException e) {
                throw new IllegalStateException(e);
            }
        });

        mHelper.onVerifyCredentialResult(VerifyCredentialResponse.credIncorrect(), newPin(REBOOT),
                PRIMARY_USER_ID);
        mHelper.onVerifyCredentialResult(VerifyCredentialResponse.OK, newPin(OWNER),
                PRIMARY_USER_ID);
        hold.countDown();
        flushHelper();

        assertThat(mReboots).isEqualTo(0);
    }

    @Test
    public void queuedReboot_notDroppedByOtherUsersVerify() throws Exception {
        setReboot(REBOOT);
        var hold = new CountDownLatch(1);
        mHelper.getBackgroundThread().getThreadHandler().post(() -> {
            try {
                hold.await();
            } catch (InterruptedException e) {
                throw new IllegalStateException(e);
            }
        });

        mHelper.onVerifyCredentialResult(VerifyCredentialResponse.credIncorrect(), newPin(REBOOT),
                PRIMARY_USER_ID);
        mHelper.onVerifyCredentialResult(VerifyCredentialResponse.OK, newPin("222200"),
                SECONDARY_USER_ID);
        hold.countDown();
        flushHelper();

        assertThat(mReboots).isEqualTo(1);
    }

    @Test
    public void enrolment_collisions() {
        assertCollision(DuressPasswordHelper.COLLISION_OWNER, () -> setReboot(OWNER));

        setDuress(DURESS_PIN, DURESS_PASSWORD);
        assertCollision(DuressPasswordHelper.COLLISION_DURESS, () -> setReboot(DURESS_PIN));
        assertCollision(DuressPasswordHelper.COLLISION_DURESS, () -> mHelper.setRebootCredential(
                newPin(OWNER), nonePassword(), newPassword(DURESS_PASSWORD), PRIMARY_USER_ID));

        setReboot(REBOOT);
        // reverse check, the old duress credentials stay
        assertCollision(DuressPasswordHelper.COLLISION_REBOOT,
                () -> setDuress(REBOOT, DURESS_PASSWORD));
        enter(newPin(DURESS_PIN), PRIMARY_USER_ID);
        assertThat(mWipes).isEqualTo(1);
    }

    @Test
    public void enrolment_wrongOwnerCredential() {
        assertThrows(SecurityException.class, () -> mHelper.setRebootCredential(newPin("000000"),
                nonePassword(), newPin(REBOOT), PRIMARY_USER_ID));
        assertThat(mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID)).isFalse();
    }

    @Test
    public void enrolment_tooShort() {
        assertThrows(IllegalArgumentException.class, () -> setReboot("12"));
    }

    @Test
    public void delete() {
        setReboot(REBOOT);
        mHelper.setRebootCredential(newPin(OWNER), nonePassword(), nonePassword(), PRIMARY_USER_ID);

        assertThat(mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID)).isFalse();
        enter(newPin(REBOOT), PRIMARY_USER_ID);
        assertThat(mReboots).isEqualTo(0);
    }

    @Test
    public void ownerScreenLockRemoved_deletesRebootCredential() {
        setReboot(REBOOT);

        mHelper.onLockCredentialChanged(nonePassword(), Primary, PRIMARY_USER_ID);

        enter(newPin(REBOOT), SECONDARY_USER_ID);
        assertThat(mReboots).isEqualTo(0);
    }

    @Test
    public void ownerCredentialEqualToRebootCredential_deletesIt() {
        setReboot(REBOOT);

        mHelper.onLockCredentialChanged(newPin(REBOOT), Primary, PRIMARY_USER_ID);

        enter(newPin(REBOOT), SECONDARY_USER_ID);
        assertThat(mReboots).isEqualTo(0);
    }

    @Test
    public void secondFactorEqualToRebootCredential_deletesIt() {
        setReboot(REBOOT);

        mHelper.onLockCredentialChanged(newPin(REBOOT), Secondary, PRIMARY_USER_ID);

        enter(newPin(REBOOT), PRIMARY_USER_ID);
        assertThat(mReboots).isEqualTo(0);
    }

    @Test
    public void unrelatedCredentialChanges_keepRebootCredential() {
        setReboot(REBOOT);

        mHelper.onLockCredentialChanged(newPin("432100"), Primary, PRIMARY_USER_ID);
        mHelper.onLockCredentialChanged(nonePassword(), Secondary, PRIMARY_USER_ID);
        // another user's credential, even an equal one
        mHelper.onLockCredentialChanged(newPin(REBOOT), Primary, SECONDARY_USER_ID);
        mHelper.onLockCredentialChanged(nonePassword(), Primary, SECONDARY_USER_ID);

        enter(newPin(REBOOT), PRIMARY_USER_ID);
        assertThat(mReboots).isEqualTo(1);
    }

    @Test
    public void corruptRebootRecord_disablesOnlyTheReboot() {
        setDuress(DURESS_PIN, DURESS_PASSWORD);
        for (String record : new String[] {"", "zz", "00", "ff", "01", "0000000004"}) {
            mStorage.setString("reboot_credential", record, PRIMARY_USER_ID);

            enter(newPin(REBOOT), PRIMARY_USER_ID);
            assertThat(mReboots).isEqualTo(0);

            var e = assertThrows(IllegalStateException.class,
                    () -> mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID));
            // fixed message, the record is never logged
            assertThat(e).hasMessageThat().isEqualTo("corrupt reboot credential record");
        }
        // duress still works, and deleting needs no parsing
        enter(newPin(DURESS_PIN), PRIMARY_USER_ID);
        assertThat(mWipes).isEqualTo(1);
        mHelper.setRebootCredential(newPin(OWNER), nonePassword(), nonePassword(), PRIMARY_USER_ID);
        assertThat(mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID)).isFalse();
    }

    @Test
    public void corruptRebootRecord_doesNotBlockDuressOrLockRemoval() {
        mStorage.setString("reboot_credential", "ff", PRIMARY_USER_ID);

        setDuress(DURESS_PIN, DURESS_PASSWORD);
        enter(newPin(DURESS_PIN), PRIMARY_USER_ID);
        assertThat(mWipes).isEqualTo(1);

        // an owner change never fails because of it, and removing the lock deletes it
        mHelper.onLockCredentialChanged(newPin("432100"), Primary, PRIMARY_USER_ID);
        mHelper.onLockCredentialChanged(nonePassword(), Primary, PRIMARY_USER_ID);
        assertThat(mStorage.getString("reboot_credential", null, PRIMARY_USER_ID)).isNull();
    }

    @Test
    public void damagedValidRecord_rejectedWithoutAllocating() {
        setReboot(REBOOT);
        String valid = mStorage.getString("reboot_credential", null, PRIMARY_USER_ID);
        // version (1 byte), PasswordData length (4), PasswordData: type (4), 3 exponents,
        // salt length (4) ..., then hash length (4) and the hash
        String[] damaged = {
                valid.substring(0, valid.length() - 2),                     // hash cut short
                valid + "00",                                               // trailing byte
                valid.substring(0, 2) + "00000024" + valid.substring(10),   // padded PasswordData
                valid.substring(0, 64) + "00000001" + valid.substring(72),  // a password handle
                valid.substring(0, 2) + "7fffffff" + valid.substring(10),   // huge outer length
                valid.substring(0, 18) + "ff" + valid.substring(20),        // scrypt exponent
                valid.substring(0, 24) + "7fffffff" + valid.substring(32),  // huge salt length
        };
        for (String record : damaged) {
            mStorage.setString("reboot_credential", record, PRIMARY_USER_ID);
            var e = assertThrows(IllegalStateException.class,
                    () -> mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID));
            assertThat(e).hasMessageThat().isEqualTo("corrupt reboot credential record");
            enter(newPin(REBOOT), PRIMARY_USER_ID);
        }
        assertThat(mReboots).isEqualTo(0);

        mStorage.setString("reboot_credential", valid, PRIMARY_USER_ID);
        enter(newPin(REBOOT), PRIMARY_USER_ID);
        assertThat(mReboots).isEqualTo(1);
    }

    @Test
    public void secondFactor_requiredAndCompared() {
        final String secondFactor = "246810";
        assertTrue(mService.setLockCredential(newPin(secondFactor), newPin(OWNER), Secondary,
                PRIMARY_USER_ID));

        // missing or wrong second factor
        assertThrows(SecurityException.class, () -> setReboot(REBOOT));
        assertThrows(SecurityException.class, () -> mHelper.setRebootCredential(newPin(OWNER),
                newPin("135790"), newPin(REBOOT), PRIMARY_USER_ID));
        assertCollision(DuressPasswordHelper.COLLISION_SECOND_FACTOR,
                () -> mHelper.setRebootCredential(newPin(OWNER), newPin(secondFactor),
                        newPin(secondFactor), PRIMARY_USER_ID));

        mHelper.setRebootCredential(newPin(OWNER), newPin(secondFactor), newPin(REBOOT), PRIMARY_USER_ID);
        enter(newPin(REBOOT), PRIMARY_USER_ID);
        assertThat(mReboots).isEqualTo(1);
    }

    @Test
    public void enrolment_refusedWhenOwnerCredentialChangesMeanwhile() {
        mHelper = new DuressPasswordHelper(mService, mStorage, mSpManager,
                new DuressPasswordHelper.Actions() {
                    @Override
                    public void wipe() {
                    }

                    @Override
                    public void reboot() {
                    }
                }) {
            @Override
            void afterOwnerChecks() {
                // an owner change starts after the checks and hasn't finished at the save
                onLockCredentialChanging(PRIMARY_USER_ID);
            }
        };

        var e = assertThrows(IllegalStateException.class, () -> setReboot(REBOOT));
        assertThat(e).hasMessageThat().isEqualTo(DuressPasswordHelper.OWNER_CREDENTIAL_CHANGED);
        assertThat(mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID)).isFalse();
    }

    @Test
    public void wiring_credentialChangesReachTheHelper() {
        DuressPasswordHelper mock = mService.duressPasswordHelper;
        reset(mock);

        assertTrue(mService.setLockCredential(newPin("432100"), newPin(OWNER), PRIMARY_USER_ID));
        verify(mock).onLockCredentialChanging(PRIMARY_USER_ID);
        verify(mock).onLockCredentialChanged(any(), eq(Primary), eq(PRIMARY_USER_ID));

        assertTrue(mService.setLockCredential(nonePassword(), newPin("432100"), PRIMARY_USER_ID));
        verify(mock).onLockCredentialChanged(argThat(c -> c.getType() == CREDENTIAL_TYPE_NONE),
                eq(Primary), eq(PRIMARY_USER_ID));
    }

    @Test
    public void wiring_verificationsReachTheHelper() {
        DuressPasswordHelper mock = mService.duressPasswordHelper;
        reset(mock);

        mService.verifyCredential(newPin("000000"), PRIMARY_USER_ID, 0);
        verify(mock).onVerifyCredentialResult(argThat(r -> !r.isMatched()), any(),
                eq(PRIMARY_USER_ID));
        mService.verifyCredential(newPin(OWNER), PRIMARY_USER_ID, 0);
        verify(mock).onVerifyCredentialResult(argThat(r -> r.isMatched()), any(),
                eq(PRIMARY_USER_ID));
    }

    private static final String PROTECTED = "222200";
    private static final int SECONDARY_SERIAL = 7;

    // a secondary user with a screen lock that manages the alternates
    private void makeSecondaryTheAuthority() {
        mService.initializeSyntheticPassword(SECONDARY_USER_ID);
        assertTrue(mService.setLockCredential(newPin(PROTECTED), nonePassword(),
                SECONDARY_USER_ID));
        mHelper.setAuthority(SECONDARY_USER_ID, SECONDARY_SERIAL);
    }

    @Test
    public void authority_defaultsToTheOwner() {
        assertThat(mHelper.getAuthorityUserId()).isEqualTo(PRIMARY_USER_ID);
        var e = assertThrows(SecurityException.class, () -> mHelper.setRebootCredential(
                newPin(PROTECTED), nonePassword(), newPin(REBOOT), SECONDARY_USER_ID));
        assertThat(e).hasMessageThat().isEqualTo(DuressPasswordHelper.NOT_AUTHORITY);
    }

    @Test
    public void authority_secondaryUserManagesTheAlternates() {
        makeSecondaryTheAuthority();

        mHelper.setRebootCredential(newPin(PROTECTED), nonePassword(), newPin(REBOOT),
                SECONDARY_USER_ID);
        mHelper.setDuressCredentials(newPin(PROTECTED), newPin(DURESS_PIN),
                newPassword(DURESS_PASSWORD), SECONDARY_USER_ID);
        assertThat(mHelper.hasRebootCredential(newPin(PROTECTED), SECONDARY_USER_ID)).isTrue();
        assertThat(mHelper.hasDuressCredentials(newPin(PROTECTED), SECONDARY_USER_ID)).isTrue();

        // the owner no longer can, even with the right credential
        assertThrows(SecurityException.class,
                () -> mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID));
        assertThrows(SecurityException.class, () -> mHelper.setDuressCredentials(newPin(OWNER),
                nonePassword(), nonePassword(), PRIMARY_USER_ID));
        // a wrong credential of the authority is refused as before
        assertThrows(SecurityException.class,
                () -> mHelper.hasRebootCredential(newPin("000000"), SECONDARY_USER_ID));

        // the alternates still fire at every user's prompt
        enter(newPin(REBOOT), PRIMARY_USER_ID);
        assertThat(mReboots).isEqualTo(1);
        enter(newPin(DURESS_PIN), SECONDARY_USER_ID);
        assertThat(mWipes).isEqualTo(1);
    }

    @Test
    public void authority_collisionsUseTheAuthoritysCredential() {
        makeSecondaryTheAuthority();
        assertCollision(DuressPasswordHelper.COLLISION_OWNER, () -> mHelper.setRebootCredential(
                newPin(PROTECTED), nonePassword(), newPin(PROTECTED), SECONDARY_USER_ID));
    }

    @Test
    public void authority_changeDeletesTheRebootCredentialOnly() {
        setReboot(REBOOT);
        setDuress(DURESS_PIN, DURESS_PASSWORD);
        makeSecondaryTheAuthority();

        assertThat(mHelper.hasRebootCredential(newPin(PROTECTED), SECONDARY_USER_ID)).isFalse();
        assertThat(mHelper.hasDuressCredentials(newPin(PROTECTED), SECONDARY_USER_ID)).isTrue();
        enter(newPin(REBOOT), PRIMARY_USER_ID);
        assertThat(mReboots).isEqualTo(0);
    }

    @Test
    public void authority_credentialChangesFollowTheAuthority() {
        makeSecondaryTheAuthority();
        mHelper.setRebootCredential(newPin(PROTECTED), nonePassword(), newPin(REBOOT),
                SECONDARY_USER_ID);

        // the owner's changes don't touch it any more
        mHelper.onLockCredentialChanged(newPin(REBOOT), Primary, PRIMARY_USER_ID);
        mHelper.onLockCredentialChanged(nonePassword(), Primary, PRIMARY_USER_ID);
        enter(newPin(REBOOT), PRIMARY_USER_ID);
        assertThat(mReboots).isEqualTo(1);

        // the authority removing its lock deletes it
        mHelper.onLockCredentialChanged(nonePassword(), Primary, SECONDARY_USER_ID);
        enter(newPin(REBOOT), PRIMARY_USER_ID);
        assertThat(mReboots).isEqualTo(1);
    }

    @Test
    public void authority_enrolmentRefusedWhenAuthorityChangesMeanwhile() {
        mHelper = new DuressPasswordHelper(mService, mStorage, mSpManager,
                new DuressPasswordHelper.Actions() {
                    @Override
                    public void wipe() {
                    }

                    @Override
                    public void reboot() {
                    }
                }) {
            @Override
            void afterOwnerChecks() {
                setAuthority(SECONDARY_USER_ID, SECONDARY_SERIAL);
            }
        };

        assertThrows(IllegalStateException.class, () -> setReboot(REBOOT));
        assertThat(mStorage.getString("reboot_credential", null, PRIMARY_USER_ID)).isNull();
    }

    @Test
    public void authority_removedUserHandsTheAlternatesBack() {
        makeSecondaryTheAuthority();
        mHelper.setRebootCredential(newPin(PROTECTED), nonePassword(), newPin(REBOOT),
                SECONDARY_USER_ID);

        mHelper.onUserRemoved(SECONDARY_USER_ID);
        assertThat(mHelper.getAuthorityUserId()).isEqualTo(PRIMARY_USER_ID);
        assertThat(mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID)).isFalse();
        // removing another user changes nothing
        mHelper.setAuthority(SECONDARY_USER_ID, SECONDARY_SERIAL);
        mHelper.onUserRemoved(TERTIARY_USER_ID);
        assertThat(mHelper.getAuthorityUserId()).isEqualTo(SECONDARY_USER_ID);
    }

    @Test
    public void authority_reusedUserIdDoesNotInheritIt() {
        makeSecondaryTheAuthority();
        mHelper.setRebootCredential(newPin(PROTECTED), nonePassword(), newPin(REBOOT),
                SECONDARY_USER_ID);

        // the same user, as at boot: kept
        mHelper.dropStaleAuthority(SECONDARY_USER_ID, SECONDARY_SERIAL);
        assertThat(mHelper.getAuthorityUserId()).isEqualTo(SECONDARY_USER_ID);
        // another user with the same id, or none: handed back, reboot credential gone
        mHelper.dropStaleAuthority(SECONDARY_USER_ID, SECONDARY_SERIAL + 1);
        assertThat(mHelper.getAuthorityUserId()).isEqualTo(PRIMARY_USER_ID);
        assertThat(mHelper.hasRebootCredential(newPin(OWNER), PRIMARY_USER_ID)).isFalse();
    }

    @Test
    public void reservedKeys_notReachableThroughTheGenericCalls() {
        for (String key : DuressPasswordHelper.RESERVED_KEYS) {
            assertThrows(SecurityException.class,
                    () -> mService.setString(key, "1", PRIMARY_USER_ID));
            assertThrows(SecurityException.class,
                    () -> mService.setLong(key, 1, PRIMARY_USER_ID));
            assertThrows(SecurityException.class,
                    () -> mService.setBoolean(key, true, PRIMARY_USER_ID));
            assertThrows(SecurityException.class,
                    () -> mService.getString(key, null, PRIMARY_USER_ID));
            assertThrows(SecurityException.class,
                    () -> mService.getLong(key, 0, PRIMARY_USER_ID));
            assertThrows(SecurityException.class,
                    () -> mService.getBoolean(key, false, PRIMARY_USER_ID));
        }
    }

    @Test
    public void authority_onlyTrustedCallersMaySetIt() {
        // the test runs under its own app uid
        assertThrows(SecurityException.class,
                () -> mService.setAlternatesAuthority(SECONDARY_USER_ID));
    }

    @Test
    public void authority_callsActForTheCallingUser() {
        // the test's uid belongs to user 0, so it can't act for another user
        assertThrows(SecurityException.class, () -> mService.hasRebootCredential(
                newPin(PROTECTED), SECONDARY_USER_ID));
    }

    // dispatch: the lock screen's single PIN entry, run through the service with the mocked
    // helper standing for the layout

    private DuressPasswordHelper protectedLayout() {
        mService.initializeSyntheticPassword(SECONDARY_USER_ID);
        assertTrue(mService.setLockCredential(newPin(PROTECTED), nonePassword(),
                SECONDARY_USER_ID));
        DuressPasswordHelper mock = mService.duressPasswordHelper;
        reset(mock);
        when(mock.getAuthorityUserId()).thenReturn(SECONDARY_USER_ID);
        return mock;
    }

    private VerifyCredentialResponse dispatch(String pin, int[] matched) {
        return mService.doDispatchCredential(newPin(pin), matched);
    }

    @Test
    public void dispatch_withoutLayoutChecksTheOwnerOnly() {
        DuressPasswordHelper mock = mService.duressPasswordHelper;
        reset(mock);
        int[] matched = {-1};

        assertThat(dispatch(OWNER, matched).isMatched()).isTrue();
        assertThat(matched[0]).isEqualTo(PRIMARY_USER_ID);
        assertThat(dispatch("000000", matched).isMatched()).isFalse();
        verify(mock).onVerifyCredentialResult(argThat(r -> !r.isMatched()), any(),
                eq(PRIMARY_USER_ID));
    }

    @Test
    public void dispatch_protectedPinOpensTheProtectedUser() {
        DuressPasswordHelper mock = protectedLayout();
        int[] matched = {-1};

        assertThat(dispatch(PROTECTED, matched).isMatched()).isTrue();
        assertThat(matched[0]).isEqualTo(SECONDARY_USER_ID);
        verify(mock).onVerifyCredentialResult(argThat(r -> r.isMatched()), any(),
                eq(SECONDARY_USER_ID));
        // a match is not a failed owner entry: no duress or reboot check
        verify(mock, never()).onVerifyCredentialResult(any(), any(), eq(PRIMARY_USER_ID));
    }

    @Test
    public void dispatch_ownerPinStillOpensTheOwner() {
        DuressPasswordHelper mock = protectedLayout();
        int[] matched = {-1};

        assertThat(dispatch(OWNER, matched).isMatched()).isTrue();
        assertThat(matched[0]).isEqualTo(PRIMARY_USER_ID);
        verify(mock).onVerifyCredentialResult(argThat(r -> r.isMatched()), any(),
                eq(PRIMARY_USER_ID));
        verify(mock, never()).onVerifyCredentialResult(any(), any(), eq(SECONDARY_USER_ID));
    }

    @Test
    public void dispatch_wrongPinRunsTheAlternateChecksOnce() {
        DuressPasswordHelper mock = protectedLayout();
        int[] matched = {-1};

        assertThat(dispatch("000000", matched).isMatched()).isFalse();
        assertThat(matched[0]).isEqualTo(PRIMARY_USER_ID);
        verify(mock).onVerifyCredentialResult(argThat(r -> !r.isMatched()), any(),
                eq(PRIMARY_USER_ID));
        verify(mock, never()).onVerifyCredentialResult(any(), any(), eq(SECONDARY_USER_ID));
    }

    @Test
    public void dispatch_ownerLockoutDoesNotBlockTheProtectedUser() {
        protectedLayout();
        mInjector.setTimeSinceBoot(Duration.ofSeconds(10));
        for (int i = 0; i < 5; i++) {
            mService.verifyCredential(newPin("000" + i), PRIMARY_USER_ID, 0);
        }
        assertThat(mService.verifyCredential(newPin("000900"), PRIMARY_USER_ID, 0)
                .getTimeoutAsDuration().isPositive()).isTrue();
        int[] matched = {-1};

        // a wrong entry reports the protected user's shorter lockout, so the pad stays usable
        assertThat(dispatch("000800", matched).getTimeoutAsDuration()).isEqualTo(Duration.ZERO);
        assertThat(dispatch(PROTECTED, matched).isMatched()).isTrue();
        assertThat(matched[0]).isEqualTo(SECONDARY_USER_ID);
    }

    @Test
    public void dispatch_onlyUserZeroMayCallIt() {
        // the test's uid belongs to user 0; the binder call is refused from other users, the
        // check itself needs the keyguard permission
        int[] matched = {-1};
        assertThat(mService.dispatchCredential(newPin(OWNER), matched).isMatched()).isTrue();
    }

    // a protected space as lock_settings sees it: B is the authority, the length is stored
    private void protectedSpaceWithLength(int length) {
        when(mService.duressPasswordHelper.getAuthorityUserId()).thenReturn(SECONDARY_USER_ID);
        mStorage.setInt(LockSettingsService.LAYOUT_PIN_LENGTH_KEY, length, PRIMARY_USER_ID);
    }

    @Test
    public void layout_everyPinKeepsTheStoredLength() {
        protectedSpaceWithLength(OWNER.length());
        assertThrows(IllegalArgumentException.class, () -> mService.setLockCredential(
                newPin("12345678"), newPin(OWNER), PRIMARY_USER_ID));
        assertTrue(mService.setLockCredential(newPin("123456"), newPin(OWNER), PRIMARY_USER_ID));
    }

    @Test
    public void layout_ownerKeepsAPin() {
        protectedSpaceWithLength(OWNER.length());
        assertThrows(IllegalArgumentException.class, () -> mService.setLockCredential(
                nonePassword(), newPin(OWNER), PRIMARY_USER_ID));
        assertThrows(IllegalArgumentException.class, () -> mService.setLockCredential(
                newPassword("abcdef"), newPin(OWNER), PRIMARY_USER_ID));
    }

    @Test
    public void layout_noRulesWithoutAProtectedSpace() {
        mStorage.setInt(LockSettingsService.LAYOUT_PIN_LENGTH_KEY, OWNER.length(),
                PRIMARY_USER_ID);
        assertTrue(mService.setLockCredential(newPin("12345678"), newPin(OWNER),
                PRIMARY_USER_ID));
        assertTrue(mService.setLockCredential(nonePassword(), newPin("12345678"),
                PRIMARY_USER_ID));
    }

    @Test
    public void layout_rebootCredentialIsAPin() {
        makeSecondaryTheAuthority();
        assertThrows(IllegalArgumentException.class, () -> mHelper.setRebootCredential(
                newPin(PROTECTED), nonePassword(), newPassword("reboot-pw"), SECONDARY_USER_ID));
        mHelper.setRebootCredential(newPin(PROTECTED), nonePassword(), newPin(REBOOT),
                SECONDARY_USER_ID);
    }

    @Test
    public void layout_onlyTheProtectedUserIsRefusedASharedPin() {
        mService.initializeSyntheticPassword(SECONDARY_USER_ID);
        assertTrue(mService.setLockCredential(newPin(PROTECTED), nonePassword(),
                SECONDARY_USER_ID));
        protectedSpaceWithLength(OWNER.length());

        var e = assertThrows(IllegalArgumentException.class, () -> mService.setLockCredential(
                newPin(OWNER), newPin(PROTECTED), SECONDARY_USER_ID));
        assertThat(e).hasMessageThat().startsWith("collision:");
        // user 0's refusal would tell it whether a guess is the protected PIN
        assertTrue(mService.setLockCredential(newPin(PROTECTED), newPin(OWNER), PRIMARY_USER_ID));
    }

    @Test
    public void layout_onlyTheProtectedUserIsRefusedAnAlternate() {
        mService.initializeSyntheticPassword(SECONDARY_USER_ID);
        protectedSpaceWithLength(OWNER.length());
        when(mService.duressPasswordHelper.isAlternateCredential(any())).thenReturn(true);
        var e = assertThrows(IllegalArgumentException.class, () -> mService.setLockCredential(
                newPin(DURESS_PIN), nonePassword(), SECONDARY_USER_ID));
        assertThat(e).hasMessageThat().startsWith("collision:");
        assertTrue(mService.setLockCredential(newPin(DURESS_PIN), newPin(OWNER),
                PRIMARY_USER_ID));
    }

    @Test
    public void duress_differsFromTheAuthoritysOwnPin() {
        makeSecondaryTheAuthority();
        var e = assertThrows(IllegalArgumentException.class, () -> mHelper.setDuressCredentials(
                newPin(PROTECTED), newPin(PROTECTED), newPassword(DURESS_PASSWORD),
                SECONDARY_USER_ID));
        assertThat(e).hasMessageThat().isEqualTo(DuressPasswordHelper.COLLISION_OWNER);
    }

    @Test
    public void layout_alternatesDifferFromTheOwnersPin() {
        makeSecondaryTheAuthority();
        protectedSpaceWithLength(OWNER.length());
        var e = assertThrows(IllegalArgumentException.class, () -> mHelper.setRebootCredential(
                newPin(PROTECTED), nonePassword(), newPin(OWNER), SECONDARY_USER_ID));
        assertThat(e).hasMessageThat().isEqualTo("collision: other space PIN");
        assertThrows(IllegalArgumentException.class, () -> mHelper.setDuressCredentials(
                newPin(PROTECTED), newPin(OWNER), newPassword(DURESS_PASSWORD),
                SECONDARY_USER_ID));
        mHelper.setRebootCredential(newPin(PROTECTED), nonePassword(), newPin(REBOOT),
                SECONDARY_USER_ID);
    }
}
