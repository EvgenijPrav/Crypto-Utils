package by.praviloffevg.cryptolib

import android.util.Log
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec


// Created by Yauheni Pravilau on 01.02.2019.
// Copyright (c) 2019 . All rights reserved.

class ByteKeyGenerator(private val salt: String = DEFAULT_SALT) {

    private companion object {
        private const val LOG_TAG = "ByteKeyGenerator"
        private const val ALGORITHM = "PBKDF2WithHmacSHA1"
        private const val DEFAULT_SALT = "Default salt"
    }

    internal fun hmacsha1(key: String): ByteArray {
        if (DEFAULT_SALT == salt) {
            Log.w(LOG_TAG, "Please specify custom salt to increase security")
        }
        val factory = SecretKeyFactory.getInstance(ALGORITHM)
        val keySpec = PBEKeySpec(key.toCharArray(), salt.toByteArray(), 2048, 256)
        val keyByte = factory.generateSecret(keySpec)
        return keyByte.encoded
    }
}