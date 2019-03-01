package by.praviloffevg.cryptolib.aes

import assertk.assert
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEqualTo
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.lang.IllegalArgumentException

@RunWith(RobolectricTestRunner::class)
class CryptoCBCTest {

    private val initialString = "initialString"
    private val key = "key"

    private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES256)
    private val cryptoCbc = CryptoCBC(byteKeyGenerator)

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

    @Test
    fun `should return different results when encrypting given IV`() {
        val iv = byteArrayOf(
            1, 2, 3, 4,
            1, 2, 3, 4,
            1, 2, 3, 4,
            1, 2, 3, 4
        )
        val encrypter = CryptoCBC(byteKeyGenerator, iv)
        val resultWithoutIV = cryptoCbc.encrypt(initialString, key)

        val resultWithIV = encrypter.encrypt(initialString, key)

        assert(resultWithIV).isNotEqualTo(resultWithoutIV)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `should throw an exception when initializing class given IV length less then 16 bytes`() {
        val iv = byteArrayOf(
            1, 2, 3, 4,
            1, 2, 3, 4,
            1, 2, 3, 4
        )

        CryptoCBC(byteKeyGenerator, iv)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `should throw an exception when initializing class given IV length more then 16 bytes`() {
        val iv = byteArrayOf(
            1, 2, 3, 4,
            1, 2, 3, 4,
            1, 2, 3, 4,
            1, 2, 3, 4,
            1, 2, 3, 4
        )

        CryptoCBC(byteKeyGenerator, iv)
    }

    @Test
    fun `should not fail when initializing class given IV length exactly 16 bytes`() {
        val iv = byteArrayOf(
            1, 2, 3, 4,
            1, 2, 3, 4,
            1, 2, 3, 4,
            1, 2, 3, 4
        )

        CryptoCBC(byteKeyGenerator, iv)
    }

}