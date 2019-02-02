package by.praviloffevg.cryptolib

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException


// Created by Yauheni Pravilau on 02.02.2019.
// Copyright (c) 2019 . All rights reserved.

class Hash {

    fun getHashV2(input: String, algorithm: Algorithms): String? {
        try {
            val messageDigest = MessageDigest.getInstance(algorithm.type)
            messageDigest.reset()
            messageDigest.update(input.toByteArray())
            val bytes = messageDigest.digest()
            val sb = StringBuilder(bytes.size shl 1)
            for (aByte in bytes) {
                sb.append(Character.forDigit(aByte.toInt() and 0xf0 shr 4, 16))
                sb.append(Character.forDigit((aByte.toInt() and 0x0f), 16))
            }
            return sb.toString()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            return null
        }

    }
}