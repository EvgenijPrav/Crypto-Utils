package by.praviloffevg.cryptolib.hash

import java.security.MessageDigest

// Created by Yauheni Pravilau on 02.02.2019.
// Copyright (c) 2019 . All rights reserved.

object HashUtil {

    private const val RADIX = 16
    private const val RIGHT_SHIFT = 4
    private const val LEFT_SHIFT = 1

    fun getHash(input: String, algorithm: Algorithms): String {
        val messageDigest = MessageDigest.getInstance(algorithm.type)
        messageDigest.reset()
        messageDigest.update(input.toByteArray())
        val bytes = messageDigest.digest()
        val sb = StringBuilder(bytes.size shl LEFT_SHIFT)
        for (aByte in bytes) {
            sb.append(Character.forDigit(aByte.toInt() and 0xf0 shr RIGHT_SHIFT, RADIX))
            sb.append(Character.forDigit((aByte.toInt() and 0x0f), RADIX))
        }
        return sb.toString()
    }
}
