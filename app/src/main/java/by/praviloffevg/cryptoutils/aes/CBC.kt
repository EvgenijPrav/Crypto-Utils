package by.praviloffevg.cryptoutils.aes

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

// Created by Yauheni Pravilau on 01.02.2019.
// Copyright (c) 2019 . All rights reserved.

class CBC(byteKeyGenerator: ByteKeyGenerator, iv: ByteArray) : Aes(byteKeyGenerator, iv) {

    constructor(byteKeyGenerator: ByteKeyGenerator) : this(
        byteKeyGenerator, byteArrayOf(
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        )
    )

    init {
        cipher = Cipher.getInstance(CYPHER)
    }

    private companion object {
        private const val CYPHER = "AES/CBC/PKCS5padding"
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun encrypt(textToEncrypt: ByteArray, key: String): String {
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(key), ivParameterSpec)
        return super.encrypt(textToEncrypt, key)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun encrypt(textToEncrypt: String, key: String): String {
        return encrypt(textToEncrypt.toByteArray(), key)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun decryptIntoByteArray(textToDecrypt: String, key: String): ByteArray {
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key), ivParameterSpec)
        return super.decryptIntoByteArray(textToDecrypt, key)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun decryptIntoString(textToDecrypt: String, key: String): String {
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key), ivParameterSpec)
        return super.decryptIntoString(textToDecrypt, key)
    }
}
