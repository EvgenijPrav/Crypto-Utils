@file:Suppress("DEPRECATION")

package by.praviloffevg.cryptoutils.rsa

import androidx.test.InstrumentationRegistry
import androidx.test.runner.AndroidJUnit4
import assertk.assert
import assertk.assertions.isEqualTo
import assertk.fail
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RsaProviderTest {
    private val keyValidationProperties = KeyValidationProperties(KeyDurationPeriod.SECOND, 10)
    private val keyAlias = "testKey"
    private val keyOwner = "testOwner"
    private val organizationName = "testOrganization"
    private val keyProperties = KeyProperties(keyAlias, keyOwner, organizationName, keyValidationProperties)
    private val context = InstrumentationRegistry.getTargetContext()
    private val initialString = "initialString".toByteArray()
    private val sleepThreshold = 10100L

    private lateinit var rsa: Rsa

    @Before
    fun setup() {
        rsa = RsaProvider(context, keyProperties)
    }

    @After
    fun dropKeys() {
        rsa.deleteKeys()
    }

    @Test
    fun shouldKeyBeNotExpiredWhenDurationPeriodDidNotPass() {
        val isExpired = rsa.isKeyExpired()

        assert(isExpired).isEqualTo(false)
    }

    @Test
    fun shouldKeyBeExpiredWhenDurationPeriodPassed() {
        Thread.sleep(sleepThreshold)
        val isExpired = rsa.isKeyExpired()

        assert(isExpired).isEqualTo(true)
    }

    @Test
    fun shouldThrowExceptionWhenCheckingExpirationGivenKeyDeleted() {
        rsa.deleteKeys()

        try {
            rsa.isKeyExpired()
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                return
            }
        }
        fail("Key has been deleted")
    }

    @Test
    fun shouldReturnSameValueWhenEncryptedAndDecrypted() {
        val encryptedString = rsa.encrypt(initialString)

        assert { rsa.decrypt(encryptedString).contentEquals(initialString) }
    }

    @Test(expected = Exception::class)
    fun shouldThrowExceptionWhenDecryptingGivenWrongInputParameter() {
        rsa.decrypt(initialString)
    }

    @Test
    fun shouldReturnSameValueWhenEncryptedAndDecryptedGivenProvidedPublicKey() {
        val publicKey = rsa.getPublicKey()

        val encryptedString = rsa.encryptWithProvidedPublicKey(initialString, publicKey)

        assert { rsa.decrypt(encryptedString).contentEquals(initialString) }
    }

    @Test
    fun shouldThrowExceptionWhenEncryptingGivenDurationPeriodPassed() {
        Thread.sleep(sleepThreshold)

        try {
            rsa.encrypt(initialString)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_EXPIRED)
                return
        }
        fail("Exception hadn't been thrown")
    }

    @Test
    fun shouldThrowExceptionWhenDecryptingGivenDurationPeriodPassed() {
        val encrypted = rsa.encrypt(initialString)
        Thread.sleep(sleepThreshold)

        try {
            rsa.decrypt(encrypted)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_EXPIRED)
                return
        }
        fail("Exception hadn't been thrown")
    }

    @Test(expected = Exception::class)
    fun shouldThrowExceptionWhenDecryptingGivenEncryptedWithAnotherPublicKey() {
        val keyAlias = "anotherKey"
        val keyProperties = KeyProperties(keyAlias, keyOwner, organizationName, keyValidationProperties)
        val rsa = RsaProvider(context, keyProperties)
        val publicKey = rsa.getPublicKey()
        val encrypted = this.rsa.encryptWithProvidedPublicKey(initialString, publicKey)

        this.rsa.decrypt(encrypted)
    }

    @Test
    fun shouldThrowExceptionWhenEncryptingGivenKeyDeleted() {
        rsa.deleteKeys()

        try {
            rsa.encrypt(initialString)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                return
            }
        }
        fail("Key has been deleted")
    }

    @Test
    fun shouldThrowExceptionWhenDecryptingGivenKeyDeleted() {
        val encrypted = rsa.encrypt(initialString)
        rsa.deleteKeys()

        try {
            rsa.decrypt(encrypted)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                return
            }
        }
        fail("Key has been deleted")
    }

    @Test
    fun shouldNotThrowExceptionWhenEncryptingGivenKeyDeletedAndCreatedNew() {
        rsa.deleteKeys()
        rsa.createNewKeys()

        try {
            rsa.encrypt(initialString)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                fail("Key should exist")
            }
        }
    }

    @Test
    fun shouldNotThrowExceptionWhenEncryptingGivenOldKeyDurationPeriodPassedAndKeyDeletedAndCreatedNew() {
        Thread.sleep(sleepThreshold)
        rsa.deleteKeys()
        rsa.createNewKeys()

        try {
            rsa.encrypt(initialString)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                fail("Key should exist")
            }
        }
    }

    @Test(expected = Exception::class)
    fun shouldThrowExceptionWhenDecryptingGivenKeyDeletedAndCreatedNew() {
        val encrypted = rsa.encrypt(initialString)
        rsa.deleteKeys()
        rsa.createNewKeys()

        rsa.decrypt(encrypted)
    }

}
