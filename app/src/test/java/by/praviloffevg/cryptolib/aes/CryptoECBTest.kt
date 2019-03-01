package by.praviloffevg.cryptolib.aes

import assertk.assert
import assertk.assertions.isEqualTo
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CryptoECBTest {
    private val initialString = "initialString"
    private val key = "key"

    private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES256)
    private val cryptoEcb= CryptoECB(byteKeyGenerator)

    @Test
    fun shouldEncryptAndDecryptIntoStringGivenString() {
        val encryptedString = cryptoEcb.encrypt(initialString, key)

        val decryptedString = cryptoEcb.decryptIntoString(encryptedString, key)

        assert(decryptedString).isEqualTo(initialString)
    }

    @Test
    fun shouldEncryptAndDecryptIntoStringGivenByteArray() {
        val encryptedString = cryptoEcb.encrypt(initialString.toByteArray(), key)

        val decryptedString = cryptoEcb.decryptIntoString(encryptedString, key)

        assert(decryptedString).isEqualTo(initialString)
    }

    @Test
    fun shouldEncryptAndDecryptIntoByteArrayGivenString() {
        val encryptedString = cryptoEcb.encrypt(initialString, key)

        val decrypted = cryptoEcb.decryptIntoByteArray(encryptedString, key)

        assert(String(decrypted)).isEqualTo(initialString)
    }

    @Test
    fun shouldEncryptAndDecryptIntoByteArrayGivenByteArray() {
        val encryptedString = cryptoEcb.encrypt(initialString.toByteArray(), key)

        val decrypted = cryptoEcb.decryptIntoByteArray(encryptedString, key)

        assert(String(decrypted)).isEqualTo(initialString)
    }

    @Test
    fun shouldEncrypt() {
        val expectedString = "R7TY6Qn2+bjknjuBWBuUJw==\n"

        val encryptedString = cryptoEcb.encrypt(initialString, key)

        assert(encryptedString).isEqualTo(expectedString)
    }
}