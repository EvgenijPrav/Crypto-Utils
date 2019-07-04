package by.praviloffevg.cryptolib.rsa

import androidx.test.InstrumentationRegistry
import androidx.test.runner.AndroidJUnit4
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

        assertk.assert(isExpired).isEqualTo(false)
    }

    @Test
    fun shouldKeyBeExpiredWhenDurationPeriodPassed() {
        Thread.sleep(10100)
        val isExpired = rsaProvider.isKeyExpired()

        assertk.assert(isExpired).isEqualTo(true)
    }

    @Test
    fun shouldReturnSameValueWhenEncryptedAndDecrypted() {
        val initialString = "initialString"

        val encryptedString = rsaProvider.encrypt(initialString)

        assertk.assert(rsaProvider.decrypt(encryptedString)).isEqualTo(initialString)
    }

    @Test
    fun shouldReturnSameValueWhenEncryptedAndDecryptedGivenProvidedPublicKey() {
        val initialString = "initialString"
        val publicKey = rsaProvider.getPublicKey()

        val encryptedString = rsaProvider.encryptWithProvidedPublicKey(initialString, publicKey)

        assertk.assert(rsaProvider.decrypt(encryptedString)).isEqualTo(initialString)
    }

    @Test
    fun shouldThrowExceptionWhenEncryptedAndDecryptedDurationPeriodPassed() {
        val initialString = "initialString"
        Thread.sleep(10100)
        try {
            rsaProvider.encrypt(initialString)
        } catch (e: Exception) {
            return
        }
        fail("Exception hadn't been thrown")
    }
}