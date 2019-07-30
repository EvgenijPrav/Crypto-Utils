package by.praviloffevg.cryptoutils.aes

interface Aes {
    fun encrypt(textToEncrypt: ByteArray, key: String): String
    fun encrypt(textToEncrypt: String, key: String): String
    fun decryptIntoByteArray(textToDecrypt: String, key: String): ByteArray
    fun decryptIntoString(textToDecrypt: String, key: String): String
}
