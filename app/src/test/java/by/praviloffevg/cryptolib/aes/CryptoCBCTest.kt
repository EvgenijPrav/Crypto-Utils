package by.praviloffevg.cryptolib.aes

import assertk.assert
import assertk.assertions.containsExactly
import assertk.assertions.isEqualTo
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class CryptoCBCTest {

    private val initialString = "initialString"
    private val key = "key"

    private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES256)
    private val cryptoCbc= CryptoCBC(byteKeyGenerator)

    @Test
    fun shouldEncryptAndDecryptIntoStringGivenString() {
        val encryptedString = cryptoCbc.encrypt(initialString, key)

        val decryptedString = cryptoCbc.decryptIntoString(encryptedString, key)

        assert(decryptedString).isEqualTo(initialString)
    }

    @Test
    fun shouldEncryptAndDecryptIntoStringGivenByteArray() {
        val encryptedString = cryptoCbc.encrypt(initialString.toByteArray(), key)

        val decryptedString = cryptoCbc.decryptIntoString(encryptedString, key)

        assert(decryptedString).isEqualTo(initialString)
    }

    @Test
    fun shouldEncryptAndDecryptIntoByteArrayGivenString() {
        val encryptedString = cryptoCbc.encrypt(initialString, key)

        val decrypted = cryptoCbc.decryptIntoByteArray(encryptedString, key)

        assert(String(decrypted)).isEqualTo(initialString)
    }

    @Test
    fun shouldEncryptAndDecryptIntoByteArrayGivenByteArray() {
        val encryptedString = cryptoCbc.encrypt(initialString.toByteArray(), key)

        val decrypted = cryptoCbc.decryptIntoByteArray(encryptedString, key)

        assert(String(decrypted)).isEqualTo(initialString)
    }

    @Test
    fun shouldEncrypt() {
        val expectedString = "R7TY6Qn2+bjknjuBWBuUJw==\n"

        val encryptedString = cryptoCbc.encrypt(initialString, key)

        assert(encryptedString).isEqualTo(expectedString)
    }
}