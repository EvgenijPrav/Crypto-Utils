package by.praviloffevg.cryptoutils.aes

import android.util.Base64
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

abstract class Aes
internal constructor(private val byteKeyGenerator: ByteKeyGenerator, iv: ByteArray) {

    protected lateinit var cipher: Cipher

    init {
        if (iv.size != DEFAULT_IV_SIZE) {
            throw IllegalArgumentException("IV must be 16 bytes long")
        }
    }

    protected companion object {
        private const val DEFAULT_IV_SIZE = 16
        private const val ALGORITHM = "AES"
    }

    protected val ivParameterSpec = IvParameterSpec(iv)

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    open fun encrypt(textToEncrypt: ByteArray, key: String): String {
        val encryptedData = cipher.doFinal(textToEncrypt)
        return Base64.encodeToString(encryptedData, Base64.NO_CLOSE)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    open fun encrypt(textToEncrypt: String, key: String): String {
        return encrypt(textToEncrypt.toByteArray(), key)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    open fun decryptIntoByteArray(textToDecrypt: String, key: String): ByteArray {
        return cipher.doFinal(Base64.decode(textToDecrypt, Base64.NO_CLOSE))
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    open fun decryptIntoString(textToDecrypt: String, key: String): String {
        return String(cipher.doFinal(Base64.decode(textToDecrypt, Base64.NO_CLOSE)))
    }

    protected fun getSecretKeySpec(key: String): SecretKeySpec {
        val verifiedKey = byteKeyGenerator.hmacsha1(key)
        return SecretKeySpec(verifiedKey, ALGORITHM)
    }
}