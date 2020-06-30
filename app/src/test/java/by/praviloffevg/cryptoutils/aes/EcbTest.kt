package by.praviloffevg.cryptoutils.aes

import android.os.Build
import assertk.assert
import assertk.assertions.isEqualTo
import by.praviloffevg.cryptoutils.TestUtils.byteArrayOfInts
import org.junit.Test
import org.junit.experimental.runners.Enclosed
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(Enclosed::class)
class EcbTest {
    @RunWith(RobolectricTestRunner::class)
    @Config(sdk = [Build.VERSION_CODES.P])
    class EcbTestAes256 {
        private val initialValue = "initialString"
        private val key = charArrayOf('k', 'e', 'y')

        private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES256)
        private val cryptoEcb = Ecb(byteKeyGenerator)

        @Test
        fun shouldEncryptAndDecryptGivenString() {
            val encrypted = cryptoEcb.encrypt(initialValue, key)

            val decrypted = cryptoEcb.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptGivenByteArray() {
            val encrypted = cryptoEcb.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoEcb.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenString() {
            val encrypted = cryptoEcb.encrypt(initialValue, key)

            val decrypted = cryptoEcb.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenByteArray() {
            val encrypted = cryptoEcb.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoEcb.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncrypt() {
            val expected = byteArrayOfInts(0x47, 0xB4, 0xD8, 0xE9, 0x09, 0xF6, 0xF9, 0xB8, 0xE4, 0x9E, 0x3B, 0x81, 0x58, 0x1B, 0x94, 0x27)

            val encrypted = cryptoEcb.encrypt(initialValue, key)

            assert { encrypted.contentEquals(expected) }
        }
    }

    @RunWith(RobolectricTestRunner::class)
    @Config(sdk = [Build.VERSION_CODES.P])
    class EcbTestAes192 {
        private val initialValue = "initialString"
        private val key = charArrayOf('k', 'e', 'y')

        private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES192)
        private val cryptoEcb = Ecb(byteKeyGenerator)

        @Test
        fun shouldEncryptAndDecryptGivenString() {
            val encrypted = cryptoEcb.encrypt(initialValue, key)

            val decrypted = cryptoEcb.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptGivenByteArray() {
            val encrypted = cryptoEcb.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoEcb.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenString() {
            val encrypted = cryptoEcb.encrypt(initialValue, key)

            val decrypted = cryptoEcb.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenByteArray() {
            val encrypted = cryptoEcb.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoEcb.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncrypt() {
            val expected = byteArrayOfInts(0x75, 0xAE, 0xAB, 0x21, 0x55, 0xB3, 0xE4, 0xC8, 0x78, 0xB9, 0xB3, 0x0C, 0x90, 0x40, 0xE8, 0xF4)

            val encrypted = cryptoEcb.encrypt(initialValue, key)

            assert { encrypted.contentEquals(expected) }
        }
    }

    @RunWith(RobolectricTestRunner::class)
    @Config(sdk = [Build.VERSION_CODES.P])
    class EcbTestAes128 {
        private val initialValue = "initialString"
        private val key = charArrayOf('k', 'e', 'y')

        private val byteKeyGenerator = ByteKeyGenerator(AesKeySpecification.AES128)
        private val cryptoEcb = Ecb(byteKeyGenerator)

        @Test
        fun shouldEncryptAndDecryptGivenString() {
            val encrypted = cryptoEcb.encrypt(initialValue, key)

            val decrypted = cryptoEcb.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptGivenByteArray() {
            val encrypted = cryptoEcb.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoEcb.decryptIntoString(encrypted, key)

            assert(decrypted).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenString() {
            val encrypted = cryptoEcb.encrypt(initialValue, key)

            val decrypted = cryptoEcb.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncryptAndDecryptIntoByteArrayGivenByteArray() {
            val encrypted = cryptoEcb.encrypt(initialValue.toByteArray(), key)

            val decrypted = cryptoEcb.decryptIntoByteArray(encrypted, key)

            assert(String(decrypted)).isEqualTo(initialValue)
        }

        @Test
        fun shouldEncrypt() {
            val expected = byteArrayOfInts(0x5A, 0x23, 0xED, 0x6F, 0x6A, 0x65, 0x12, 0x1C, 0x69, 0xF6, 0xE8, 0xF0, 0x19, 0xAB, 0xAE, 0xC7)

            val encrypted = cryptoEcb.encrypt(initialValue, key)

            assert { encrypted.contentEquals(expected) }
        }
    }
}
