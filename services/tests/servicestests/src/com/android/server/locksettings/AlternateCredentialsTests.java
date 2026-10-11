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
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

import android.platform.test.annotations.Presubmit;

import androidx.test.filters.SmallTest;
import androidx.test.runner.AndroidJUnit4;

import com.android.internal.widget.LockscreenCredential;
import com.android.internal.widget.VerifyCredentialResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;

/** Duress and reboot credentials, with the real helper and actions that only count calls. */
@SmallTest
@Presubmit
@RunWith(AndroidJUnit4.class)
public class AlternateCredentialsTests extends BaseLockSettingsServiceTests {
    private static final String OWNER = "1111";
    private static final String DURESS_PIN = "9999";
    private static final String DURESS_PASSWORD = "duress-pw";
    private static final String REBOOT = "5555";

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
        mHelper.setRebootCredential(newPin(OWNER), nonePassword(), newPin(pin));
    }

    private void setDuress(String pin, String password) {
        mHelper.setDuressCredentials(newPin(OWNER), newPin(pin), newPassword(password));
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
        assertThat(mHelper.hasRebootCredential(newPin(OWNER))).isTrue();

        enter(newPin(REBOOT), PRIMARY_USER_ID);
        enter(newPin(REBOOT), SECONDARY_USER_ID);

        assertThat(mReboots).isEqualTo(2);
        assertThat(mWipes).isEqualTo(0);
    }

    @Test
    public void rebootCredential_otherCredentialsDoNothing() {
        setReboot(REBOOT);

        enter(newPin("0000"), PRIMARY_USER_ID);
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
        mHelper.setRebootCredential(newPin(OWNER), nonePassword(), newPassword("reboot-pw"));

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
        mHelper.onVerifyCredentialResult(VerifyCredentialResponse.OK, newPin("2222"),
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
                newPin(OWNER), nonePassword(), newPassword(DURESS_PASSWORD)));

        setReboot(REBOOT);
        // reverse check, the old duress credentials stay
        assertCollision(DuressPasswordHelper.COLLISION_REBOOT,
                () -> setDuress(REBOOT, DURESS_PASSWORD));
        enter(newPin(DURESS_PIN), PRIMARY_USER_ID);
        assertThat(mWipes).isEqualTo(1);
    }

    @Test
    public void enrolment_wrongOwnerCredential() {
        assertThrows(SecurityException.class, () -> mHelper.setRebootCredential(newPin("0000"),
                nonePassword(), newPin(REBOOT)));
        assertThat(mHelper.hasRebootCredential(newPin(OWNER))).isFalse();
    }

    @Test
    public void enrolment_tooShort() {
        assertThrows(IllegalArgumentException.class, () -> setReboot("12"));
    }

    @Test
    public void delete() {
        setReboot(REBOOT);
        mHelper.setRebootCredential(newPin(OWNER), nonePassword(), nonePassword());

        assertThat(mHelper.hasRebootCredential(newPin(OWNER))).isFalse();
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

        mHelper.onLockCredentialChanged(newPin("4321"), Primary, PRIMARY_USER_ID);
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
                    () -> mHelper.hasRebootCredential(newPin(OWNER)));
            // fixed message, the record is never logged
            assertThat(e).hasMessageThat().isEqualTo("corrupt reboot credential record");
        }
        // duress still works, and deleting needs no parsing
        enter(newPin(DURESS_PIN), PRIMARY_USER_ID);
        assertThat(mWipes).isEqualTo(1);
        mHelper.setRebootCredential(newPin(OWNER), nonePassword(), nonePassword());
        assertThat(mHelper.hasRebootCredential(newPin(OWNER))).isFalse();
    }

    @Test
    public void corruptRebootRecord_doesNotBlockDuressOrLockRemoval() {
        mStorage.setString("reboot_credential", "ff", PRIMARY_USER_ID);

        setDuress(DURESS_PIN, DURESS_PASSWORD);
        enter(newPin(DURESS_PIN), PRIMARY_USER_ID);
        assertThat(mWipes).isEqualTo(1);

        // an owner change never fails because of it, and removing the lock deletes it
        mHelper.onLockCredentialChanged(newPin("4321"), Primary, PRIMARY_USER_ID);
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
                    () -> mHelper.hasRebootCredential(newPin(OWNER)));
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
                newPin("135790"), newPin(REBOOT)));
        assertCollision(DuressPasswordHelper.COLLISION_SECOND_FACTOR,
                () -> mHelper.setRebootCredential(newPin(OWNER), newPin(secondFactor),
                        newPin(secondFactor)));

        mHelper.setRebootCredential(newPin(OWNER), newPin(secondFactor), newPin(REBOOT));
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
        assertThat(mHelper.hasRebootCredential(newPin(OWNER))).isFalse();
    }

    @Test
    public void wiring_credentialChangesReachTheHelper() {
        DuressPasswordHelper mock = mService.duressPasswordHelper;
        reset(mock);

        assertTrue(mService.setLockCredential(newPin("4321"), newPin(OWNER), PRIMARY_USER_ID));
        verify(mock).onLockCredentialChanging(PRIMARY_USER_ID);
        verify(mock).onLockCredentialChanged(any(), eq(Primary), eq(PRIMARY_USER_ID));

        assertTrue(mService.setLockCredential(nonePassword(), newPin("4321"), PRIMARY_USER_ID));
        verify(mock).onLockCredentialChanged(argThat(c -> c.getType() == CREDENTIAL_TYPE_NONE),
                eq(Primary), eq(PRIMARY_USER_ID));
    }

    @Test
    public void wiring_verificationsReachTheHelper() {
        DuressPasswordHelper mock = mService.duressPasswordHelper;
        reset(mock);

        mService.verifyCredential(newPin("0000"), PRIMARY_USER_ID, 0);
        verify(mock).onVerifyCredentialResult(argThat(r -> !r.isMatched()), any(),
                eq(PRIMARY_USER_ID));
        mService.verifyCredential(newPin(OWNER), PRIMARY_USER_ID, 0);
        verify(mock).onVerifyCredentialResult(argThat(r -> r.isMatched()), any(),
                eq(PRIMARY_USER_ID));
    }
}
