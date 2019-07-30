package by.praviloffevg.cryptoutils.aes

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

class ECB(byteKeyGenerator: ByteKeyGenerator) : AesImpl(byteKeyGenerator) {

    init {
        cipher = Cipher.getInstance(CYPHER)
    }

    private companion object {
        private const val CYPHER = "AES/ECB/PKCS5padding"
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun encrypt(textToEncrypt: ByteArray, key: String): String {
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(key))
        return super.encrypt(textToEncrypt)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun decryptIntoByteArray(textToDecrypt: String, key: String): ByteArray {
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key))
        return super.decryptIntoByteArray(textToDecrypt)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun decryptIntoString(textToDecrypt: String, key: String): String {
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key))
        return super.decryptIntoString(textToDecrypt)
    }
}
