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
    private val initialString = "initialString"
    private val sleepThreshold = 10100L

    private lateinit var rsaProvider: RsaProvider

    @Before
    fun setup() {
        rsaProvider = RsaProvider(context, keyProperties)
    }

    @After
    fun dropKeys() {
        rsaProvider.deleteKey()
    }

    @Test
    fun shouldKeyBeNotExpiredWhenDurationPeriodDidNotPass() {
        val isExpired = rsaProvider.isKeyExpired()

        assert(isExpired).isEqualTo(false)
    }

    @Test
    fun shouldKeyBeExpiredWhenDurationPeriodPassed() {
        Thread.sleep(sleepThreshold)
        val isExpired = rsaProvider.isKeyExpired()

        assert(isExpired).isEqualTo(true)
    }

    @Test
    fun shouldThrowExceptionWhenCheckingExpirationGivenKeyDeleted() {
        rsaProvider.deleteKey()

        try {
            rsaProvider.isKeyExpired()
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                return
            }
        }
        fail("Key has been deleted")
    }

    @Test
    fun shouldReturnSameValueWhenEncryptedAndDecrypted() {
        val encryptedString = rsaProvider.encrypt(initialString)

        assert(rsaProvider.decrypt(encryptedString)).isEqualTo(initialString)
    }

    @Test(expected = Exception::class)
    fun shouldThrowExceptionWhenDecryptingGivenWrongInputParameter() {
        rsaProvider.decrypt(initialString)
    }

    @Test
    fun shouldReturnSameValueWhenEncryptedAndDecryptedGivenProvidedPublicKey() {
        val publicKey = rsaProvider.getPublicKey()

        val encryptedString = rsaProvider.encryptWithProvidedPublicKey(initialString, publicKey)

        assert(rsaProvider.decrypt(encryptedString)).isEqualTo(initialString)
    }

    @Test
    fun shouldThrowExceptionWhenEncryptingGivenDurationPeriodPassed() {
        Thread.sleep(sleepThreshold)

        try {
            rsaProvider.encrypt(initialString)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_EXPIRED)
                return
        }
        fail("Exception hadn't been thrown")
    }

    @Test
    fun shouldThrowExceptionWhenDecryptingGivenDurationPeriodPassed() {
        val encrypted = rsaProvider.encrypt(initialString)
        Thread.sleep(sleepThreshold)

        try {
            rsaProvider.decrypt(encrypted)
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
        val encrypted = rsaProvider.encryptWithProvidedPublicKey(initialString, publicKey)

        rsaProvider.decrypt(encrypted)
    }

    @Test
    fun shouldThrowExceptionWhenEncryptingGivenKeyDeleted() {
        rsaProvider.deleteKey()

        try {
            rsaProvider.encrypt(initialString)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                return
            }
        }
        fail("Key has been deleted")
    }

    @Test
    fun shouldThrowExceptionWhenDecryptingGivenKeyDeleted() {
        val encrypted = rsaProvider.encrypt(initialString)
        rsaProvider.deleteKey()

        try {
            rsaProvider.decrypt(encrypted)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                return
            }
        }
        fail("Key has been deleted")
    }

    @Test
    fun shouldNotThrowExceptionWhenEncryptingGivenKeyDeletedAndCreatedNew() {
        rsaProvider.deleteKey()
        rsaProvider.createNewKeys()

        try {
            rsaProvider.encrypt(initialString)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                fail("Key should exist")
            }
        }
    }

    @Test
    fun shouldNotThrowExceptionWhenEncryptingGivenOldKeyDurationPeriodPassedAndKeyDeletedAndCreatedNew() {
        Thread.sleep(sleepThreshold)
        rsaProvider.deleteKey()
        rsaProvider.createNewKeys()

        try {
            rsaProvider.encrypt(initialString)
        } catch (e: KeyValidationException) {
            if (e.code == KeyValidationException.ExceptionCode.KEY_NOT_FOUND) {
                fail("Key should exist")
            }
        }
    }

    @Test(expected = Exception::class)
    fun shouldThrowExceptionWhenDecryptingGivenKeyDeletedAndCreatedNew() {
        val encrypted = rsaProvider.encrypt(initialString)
        rsaProvider.deleteKey()
        rsaProvider.createNewKeys()

        rsaProvider.decrypt(encrypted)
    }

}