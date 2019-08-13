package by.praviloffevg.cryptoutils.aes

import assertk.assert
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEqualTo
import org.junit.Test
import org.junit.experimental.runners.Enclosed
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(Enclosed::class)
class CbcTest {
    @RunWith(RobolectricTestRunner::class)
    class CbcTestAes256 {

        private val initialString = "initialString"
        private val key = charArrayOf('k', 'e', 'y')

        private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES256)
        private val cryptoCbc = Cbc(byteKeyGenerator)

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
            val encrypter = Cbc(byteKeyGenerator, iv)
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

            Cbc(byteKeyGenerator, iv)
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

            Cbc(byteKeyGenerator, iv)
        }

        @Test
        fun `should not fail when initializing class given IV length exactly 16 bytes`() {
            val iv = byteArrayOf(
                1, 2, 3, 4,
                1, 2, 3, 4,
                1, 2, 3, 4,
                1, 2, 3, 4
            )

            Cbc(byteKeyGenerator, iv)
        }
    }

    @RunWith(RobolectricTestRunner::class)
    class CbcTestAes192 {

        private val initialString = "initialString"
        private val key = charArrayOf('k', 'e', 'y')

        private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES192)
        private val cryptoCbc = Cbc(byteKeyGenerator)

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
            val expectedString = "da6rIVWz5Mh4ubMMkEDo9A==\n"

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
            val encrypter = Cbc(byteKeyGenerator, iv)
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

            Cbc(byteKeyGenerator, iv)
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

            Cbc(byteKeyGenerator, iv)
        }

        @Test
        fun `should not fail when initializing class given IV length exactly 16 bytes`() {
            val iv = byteArrayOf(
                1, 2, 3, 4,
                1, 2, 3, 4,
                1, 2, 3, 4,
                1, 2, 3, 4
            )

            Cbc(byteKeyGenerator, iv)
        }
    }

    @RunWith(RobolectricTestRunner::class)
    class CbcTestAes128 {

        private val initialString = "initialString"
        private val key = charArrayOf('k', 'e', 'y')

        private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES128)
        private val cryptoCbc = Cbc(byteKeyGenerator)

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
            val expectedString = "WiPtb2plEhxp9ujwGauuxw==\n"

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
            val encrypter = Cbc(byteKeyGenerator, iv)
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

            Cbc(byteKeyGenerator, iv)
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

            Cbc(byteKeyGenerator, iv)
        }

        @Test
        fun `should not fail when initializing class given IV length exactly 16 bytes`() {
            val iv = byteArrayOf(
                1, 2, 3, 4,
                1, 2, 3, 4,
                1, 2, 3, 4,
                1, 2, 3, 4
            )

            Cbc(byteKeyGenerator, iv)
        }
    }
}