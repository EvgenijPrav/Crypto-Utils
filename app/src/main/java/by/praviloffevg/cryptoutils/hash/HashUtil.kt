package by.praviloffevg.cryptoutils.hash

import java.security.MessageDigest

// Created by Yauheni Pravilau on 02.02.2019.
// Copyright (c) 2019 . All rights reserved.

object HashUtil {

    private const val RADIX = 16
    private const val RIGHT_SHIFT = 4
    private const val LEFT_SHIFT = 1

    /**
     * This method allows to calculate hash value of the income parameter
     * @param input  input parameter
     * @param algorithm algorithm
     * @return hash value of the income parameter
     */
    @Suppress("MagicNumber")
    fun getHash(input: ByteArray, algorithm: Algorithms): String {
        val messageDigest = MessageDigest.getInstance(algorithm.type)
        messageDigest.reset()
        messageDigest.update(input)
        val bytes = messageDigest.digest()
        val sb = StringBuilder(bytes.size shl LEFT_SHIFT)
        for (aByte in bytes) {
            sb.append(Character.forDigit(aByte.toInt() and 0xf0 shr RIGHT_SHIFT, RADIX))
            sb.append(Character.forDigit(aByte.toInt() and 0x0f, RADIX))
        }
        return sb.toString()
    }
}
