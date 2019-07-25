package by.praviloffevg.cryptoutils.aes

import android.util.Base64
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// Created by Yauheni Pravilau on 01.02.2019.
// Copyright (c) 2019 . All rights reserved.

class CBC(private val byteKeyGenerator: ByteKeyGenerator, iv: ByteArray) {

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
    }

    private companion object {
        private const val CYPHER = "AES/CBC/PKCS5padding"
        private const val ALGORITHM = "AES"
        private const val DEFAULT_IV_SIZE = 16
    }

    private val ivParameterSpec = IvParameterSpec(iv)
    private val cipher = Cipher.getInstance(CYPHER)

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(textToEncrypt: ByteArray, key: String): String {
        val verifiedKey = byteKeyGenerator.hmacsha1(key)

        val secretKeySpec = SecretKeySpec(verifiedKey, ALGORITHM)

        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec)
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
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)
        return cipher.doFinal(Base64.decode(textToDecrypt, Base64.NO_CLOSE))
    }

    @Throws(IllegalBlockSizeException::class, BadPaddingException::class)
    fun decryptIntoString(textToDecrypt: String, key: String): String {
        val verifiedKey = byteKeyGenerator.hmacsha1(key)
        val secretKeySpec = SecretKeySpec(verifiedKey, ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec)
        return String(cipher.doFinal(Base64.decode(textToDecrypt, Base64.NO_CLOSE)))
    }
}
