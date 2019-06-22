package by.praviloffevg.cryptolib.aes

import android.annotation.SuppressLint
import android.util.Base64
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.SecretKeySpec

class CryptoECB(private val byteKeyGenerator: ByteKeyGenerator) {

    private companion object {
        private const val CYPHER = "AES/ECB/PKCS5padding"
        private const val ALGORITHM = "AES"
    }

    @SuppressLint("GetInstance")
    private val cipher = Cipher.getInstance(CYPHER)

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(textToEncrypt: ByteArray, key: String): String {
        val verifiedKey = byteKeyGenerator.hmacsha1(key)

        val secretKeySpec = SecretKeySpec(verifiedKey, ALGORITHM)

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)
        val encryptedData = cipher.doFinal(textToEncrypt)
        return Base64.encodeToString(encryptedData, Base64.NO_CLOSE)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(textToEncrypt: String, key: String): String {
        return encrypt(textToEncrypt.toByteArray(), key)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun decryptIntoByteArray(textToDecrypt: String, key: String): ByteArray {
        val verifiedKey = byteKeyGenerator.hmacsha1(key)
        val secretKeySpec = SecretKeySpec(verifiedKey, ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec)
        return cipher.doFinal(Base64.decode(textToDecrypt, Base64.NO_CLOSE))
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun decryptIntoString(textToDecrypt: String, key: String): String {
        val verifiedKey = byteKeyGenerator.hmacsha1(key)
        val secretKeySpec = SecretKeySpec(verifiedKey, ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec)
        return String(cipher.doFinal(Base64.decode(textToDecrypt, Base64.NO_CLOSE)))
    }
}