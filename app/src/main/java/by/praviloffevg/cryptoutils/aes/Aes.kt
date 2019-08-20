package by.praviloffevg.cryptoutils.aes

import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException

interface Aes {

    /**
     * This method allows to encrypt data
     * @param textToEncrypt text to encrypt
     * @param key is used to encrypt provided data
     * @return encrypted data in Base64
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(textToEncrypt: ByteArray, key: CharArray): ByteArray

    /**
     * This method allows to encrypt data
     * To increase security use [encrypt]
     * and don't store sensitive data in [String] variables
     * @param textToEncrypt text to encrypt
     * @param key is used to encrypt provided data
     * @return encrypted data in Base64
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(textToEncrypt: String, key: CharArray): ByteArray

    /**
     * This method allows to decrypt data
     * @param textToDecrypt encrypted data
     * @param key key to decrypt data
     * @return encrypted data
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun decryptIntoByteArray(textToDecrypt: ByteArray, key: CharArray): ByteArray

    /**
     * This method allows to decrypt data
     * To increase security use [decryptIntoByteArray]
     * and don't store sensitive data in [String] variables
     * @param textToDecrypt encrypted data
     * @param key key to decrypt data
     * @return encrypted data
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun decryptIntoString(textToDecrypt: ByteArray, key: CharArray): String
}
