package by.praviloffevg.cryptoutils.aes

import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException

interface Aes {

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(textToEncrypt: ByteArray, key: CharArray): String

    /**
     * To increase security use [encrypt]
     * and don't store sensitive data in [String] variables
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(textToEncrypt: String, key: CharArray): String

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun decryptIntoByteArray(textToDecrypt: String, key: CharArray): ByteArray

    /**
     * To increase security use [decryptIntoByteArray]
     * and don't store sensitive data in [String] variables
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun decryptIntoString(textToDecrypt: String, key: CharArray): String
}
