package by.praviloffevg.cryptoutils.aes

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.SecretKeySpec

abstract class AesImpl
internal constructor(private val byteKeyGenerator: ByteKeyGenerator) : Aes {

    protected lateinit var cipher: Cipher

    protected companion object {
        private const val ALGORITHM = "AES"
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    protected fun encrypt(textToEncrypt: ByteArray): ByteArray {
        return cipher.doFinal(textToEncrypt)
    }

    /**
     * This method allows to encrypt data
     * To increase security use [encrypt]
     * and don't store sensitive data in [String] variables
     * @param textToEncrypt text to encrypt
     * @param key is used to encrypt provided data
     * @return encrypted data in Base64
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun encrypt(textToEncrypt: String, key: CharArray): ByteArray {
        return encrypt(textToEncrypt.toByteArray(), key)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    protected fun decryptIntoByteArray(textToDecrypt: ByteArray): ByteArray {
        return cipher.doFinal(textToDecrypt)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    protected fun decryptIntoString(textToDecrypt: ByteArray): String {
        return String(cipher.doFinal(textToDecrypt))
    }

    protected fun getSecretKeySpec(key: CharArray): SecretKeySpec {
        val verifiedKey = byteKeyGenerator.getHmacsha1(key)
        return SecretKeySpec(verifiedKey, ALGORITHM)
    }
}
