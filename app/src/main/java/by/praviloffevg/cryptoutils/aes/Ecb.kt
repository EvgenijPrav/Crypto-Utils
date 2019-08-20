package by.praviloffevg.cryptoutils.aes

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

class Ecb(byteKeyGenerator: ByteKeyGenerator) : AesImpl(byteKeyGenerator) {

    init {
        cipher = Cipher.getInstance(CYPHER)
    }

    private companion object {
        private const val CYPHER = "AES/ECB/PKCS5padding"
    }

    /**
     * This method allows to encrypt data
     * @param textToEncrypt text to encrypt
     * @param key is used to encrypt provided data
     * @return encrypted data in Base64
     */
    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun encrypt(textToEncrypt: ByteArray, key: CharArray): ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(key))
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
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key))
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
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key))
        return super.decryptIntoString(textToDecrypt)
    }
}
