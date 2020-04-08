package by.praviloffevg.cryptoutils.aes

import android.util.Log
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.IvParameterSpec

/**
 * @param byteKeyGenerator [ByteKeyGenerator] instance
 * @param initializationVector initialization vector
 */
class Cbc(
    byteKeyGenerator: ByteKeyGenerator,
    initializationVector: ByteArray
) : AesImpl(byteKeyGenerator) {

    constructor(byteKeyGenerator: ByteKeyGenerator) : this(
        byteKeyGenerator, DEFAULT_INITIALIZATION_VECTOR
    )

    init {
        if (initializationVector.size != DEFAULT_IV_SIZE) {
            throw IllegalArgumentException("IV must be 16 bytes long")
        }
        if (DEFAULT_INITIALIZATION_VECTOR.contentEquals(initializationVector)) {
            Log.w(LOG_TAG, WARNING_MESSAGE)
        }
        cipher = Cipher.getInstance(CYPHER)
    }

    private val ivParameterSpec = IvParameterSpec(initializationVector)

    /**
     * This method allows to encrypt data
     * @param textToEncrypt text to encrypt
     * @param key is used to encrypt provided data
     * @return encrypted data in Base64
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun encrypt(textToEncrypt: ByteArray, key: CharArray): ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(key), ivParameterSpec)
        return super.encrypt(textToEncrypt)
    }

    /**
     * This method allows to decrypt data
     * @param textToDecrypt encrypted data
     * @param key key to decrypt data
     * @return encrypted data
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun decryptIntoByteArray(textToDecrypt: ByteArray, key: CharArray): ByteArray {
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key), ivParameterSpec)
        return super.decryptIntoByteArray(textToDecrypt)
    }

    /**
     * This method allows to decrypt data
     * To increase security use [decryptIntoByteArray]
     * and don't store sensitive data in [String] variables
     * @param textToDecrypt encrypted data
     * @param key key to decrypt data
     * @return encrypted data
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun decryptIntoString(textToDecrypt: ByteArray, key: CharArray): String {
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key), ivParameterSpec)
        return super.decryptIntoString(textToDecrypt)
    }

    private companion object {
        private const val CYPHER = "AES/CBC/PKCS5padding"
        private const val DEFAULT_IV_SIZE = 16
        private const val LOG_TAG = "AES/CBS"
        private const val WARNING_MESSAGE = "Please specify custom initialization vector to increase security"
        private val DEFAULT_INITIALIZATION_VECTOR = byteArrayOf(
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        )
    }
}
