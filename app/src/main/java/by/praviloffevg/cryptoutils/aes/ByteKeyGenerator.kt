package by.praviloffevg.cryptoutils.aes

import android.util.Log
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

// Created by Yauheni Pravilau on 01.02.2019.
// Copyright (c) 2019 . All rights reserved.

class ByteKeyGenerator(
    private val keySpecification: AesKeySpecification,
    private val salt: String
) {

    constructor(keySpecification: AesKeySpecification)
            : this(keySpecification, DEFAULT_SALT)

    private companion object {
        private const val LOG_TAG = "ByteKeyGenerator"
        private const val ALGORITHM = "PBKDF2WithHmacSHA1"
        private const val DEFAULT_SALT = "Default salt"
        private const val ITERATION_COUNT = 2048
    }

    internal fun hmacsha1(key: CharArray): ByteArray {
        if (DEFAULT_SALT == salt) {
            Log.w(LOG_TAG, "Please specify custom salt to increase security")
        }
        val factory = SecretKeyFactory.getInstance(ALGORITHM)
        val keySpec = PBEKeySpec(
            key,
            salt.toByteArray(),
            ITERATION_COUNT,
            keySpecification.length
        )
        val keyByte = factory.generateSecret(keySpec)
        return keyByte.encoded
    }
}
