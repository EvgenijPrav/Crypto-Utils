package by.praviloffevg.cryptoutils.aes

import assertk.assert
import assertk.assertions.isEqualTo
import assertk.assertions.isNotEqualTo
import by.praviloffevg.cryptoutils.TestUtils.byteArrayOfInts
import org.junit.Test
import org.junit.experimental.runners.Enclosed
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(Enclosed::class)
class CbcTest {
    @RunWith(RobolectricTestRunner::class)
    class CbcTestAes256 {

        private val initialValue = "initialString"
        private val key = charArrayOf('k', 'e', 'y')

        private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES256)
        private val cryptoCbc = Cbc(byteKeyGenerator)

        @Test
        fun shouldEncryptAndDecryptGivenString() {
            val encrypted = cryptoCbc.encrypt(initialValue, key)

            val decrypted = cryptoCbc.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptGivenByteArray() {
            val encrypted = cryptoCbc.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoCbc.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenString() {
            val encrypted = cryptoCbc.encrypt(initialValue, key)

            val decrypted = cryptoCbc.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenByteArray() {
            val encrypted = cryptoCbc.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoCbc.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncrypt() {
            val expected = byteArrayOfInts(0x47, 0xB4, 0xD8, 0xE9, 0x09, 0xF6, 0xF9, 0xB8, 0xE4, 0x9E, 0x3B, 0x81, 0x58, 0x1B, 0x94, 0x27)

            val encrypted = cryptoCbc.encrypt(initialValue, key)

            assert { encrypted.contentEquals(expected) }
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
            val resultWithoutIV = cryptoCbc.encrypt(initialValue, key)

            val resultWithIV = encrypter.encrypt(initialValue, key)

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

        private val initialValue = "initialString"
        private val key = charArrayOf('k', 'e', 'y')

        private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES192)
        private val cryptoCbc = Cbc(byteKeyGenerator)

        @Test
        fun shouldEncryptAndDecryptGivenString() {
            val encrypted = cryptoCbc.encrypt(initialValue, key)

            val decrypted = cryptoCbc.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptGivenByteArray() {
            val encrypted = cryptoCbc.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoCbc.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenString() {
            val encrypted = cryptoCbc.encrypt(initialValue, key)

            val decrypted = cryptoCbc.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenByteArray() {
            val encrypted = cryptoCbc.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoCbc.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncrypt() {
            val expected = byteArrayOfInts(0x75, 0xAE, 0xAB, 0x21, 0x55, 0xB3, 0xE4, 0xC8, 0x78, 0xB9, 0xB3, 0x0C, 0x90, 0x40, 0xE8, 0xF4)

            val encrypted = cryptoCbc.encrypt(initialValue, key)

            assert { encrypted.contentEquals(expected) }
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
            val resultWithoutIV = cryptoCbc.encrypt(initialValue, key)

            val resultWithIV = encrypter.encrypt(initialValue, key)

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

        private val initialValue = "initialString"
        private val key = charArrayOf('k', 'e', 'y')

        private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES128)
        private val cryptoCbc = Cbc(byteKeyGenerator)

        @Test
        fun shouldEncryptAndDecryptGivenString() {
            val encrypted = cryptoCbc.encrypt(initialValue, key)

            val decrypted = cryptoCbc.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptGivenByteArray() {
            val encrypted = cryptoCbc.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoCbc.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenString() {
            val encrypted = cryptoCbc.encrypt(initialValue, key)

            val decrypted = cryptoCbc.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenByteArray() {
            val encrypted = cryptoCbc.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoCbc.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncrypt() {
            val expected = byteArrayOfInts(0x5A, 0x23, 0xED, 0x6F, 0x6A, 0x65, 0x12, 0x1C, 0x69, 0xF6, 0xE8, 0xF0, 0x19, 0xAB, 0xAE, 0xC7)

            val encrypted = cryptoCbc.encrypt(initialValue, key)

            assert { encrypted.contentEquals(expected) }
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
            val resultWithoutIV = cryptoCbc.encrypt(initialValue, key)

            val resultWithIV = encrypter.encrypt(initialValue, key)

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