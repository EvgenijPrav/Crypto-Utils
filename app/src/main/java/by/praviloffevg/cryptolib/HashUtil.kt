package by.praviloffevg.cryptolib

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.MessageDigest
import java.security.Security


// Created by Yauheni Pravilau on 02.02.2019.
// Copyright (c) 2019 . All rights reserved.

object HashUtil {

    fun getHash(input: String, algorithm: Algorithms): String {
        Security.addProvider(BouncyCastleProvider())
        val messageDigest = MessageDigest.getInstance(
            algorithm.type,
            BouncyCastleProvider.PROVIDER_NAME
        )
        messageDigest.reset()
        messageDigest.update(input.toByteArray())
        val bytes = messageDigest.digest()
        val sb = StringBuilder(bytes.size shl 1)
        for (aByte in bytes) {
            sb.append(Character.forDigit(aByte.toInt() and 0xf0 shr 4, 16))
            sb.append(Character.forDigit((aByte.toInt() and 0x0f), 16))
        }
        return sb.toString()
    }
}