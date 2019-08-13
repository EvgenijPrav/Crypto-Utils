package by.praviloffevg.cryptoutils.aes

import android.util.Base64
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.SecretKeySpec

abstract class AesImpl
internal constructor(private val byteKeyGenerator: ByteKeyGenerator): Aes {

    protected lateinit var cipher: Cipher

    protected companion object {
        private const val ALGORITHM = "AES"
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(textToEncrypt: ByteArray): String {
        val encryptedData = cipher.doFinal(textToEncrypt)
        return Base64.encodeToString(encryptedData, Base64.NO_CLOSE)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun encrypt(textToEncrypt: String, key: CharArray): String {
        return encrypt(textToEncrypt.toByteArray(), key)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun decryptIntoByteArray(textToDecrypt: String): ByteArray {
        return cipher.doFinal(Base64.decode(textToDecrypt, Base64.NO_CLOSE))
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun decryptIntoString(textToDecrypt: String): String {
        return String(cipher.doFinal(Base64.decode(textToDecrypt, Base64.NO_CLOSE)))
    }

    protected fun getSecretKeySpec(key: CharArray): SecretKeySpec {
        val verifiedKey = byteKeyGenerator.hmacsha1(key)
        return SecretKeySpec(verifiedKey, ALGORITHM)
    }
}
