package by.praviloffevg.cryptoutils.aes

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.IvParameterSpec

// Created by Yauheni Pravilau on 01.02.2019.
// Copyright (c) 2019 . All rights reserved.

class Cbc(byteKeyGenerator: ByteKeyGenerator, iv: ByteArray) : AesImpl(byteKeyGenerator) {

    constructor(byteKeyGenerator: ByteKeyGenerator) : this(
        byteKeyGenerator, byteArrayOf(
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        )
    )

    init {
        if (iv.size != DEFAULT_IV_SIZE) {
            throw IllegalArgumentException("IV must be 16 bytes long")
        }
        cipher = Cipher.getInstance(CYPHER)
    }

    private val ivParameterSpec = IvParameterSpec(iv)

    private companion object {
        private const val CYPHER = "AES/CBC/PKCS5padding"
        private const val DEFAULT_IV_SIZE = 16
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun encrypt(textToEncrypt: ByteArray, key: CharArray): String {
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKeySpec(key), ivParameterSpec)
        return super.encrypt(textToEncrypt)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun decryptIntoByteArray(textToDecrypt: String, key: CharArray): ByteArray {
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key), ivParameterSpec)
        return super.decryptIntoByteArray(textToDecrypt)
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    override fun decryptIntoString(textToDecrypt: String, key: CharArray): String {
        cipher.init(Cipher.DECRYPT_MODE, getSecretKeySpec(key), ivParameterSpec)
        return super.decryptIntoString(textToDecrypt)
    }
}
