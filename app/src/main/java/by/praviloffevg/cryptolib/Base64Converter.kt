package by.praviloffevg.cryptolib

// Created by Yauheni Pravilau on 01.02.2019.
// Copyright (c) 2019 . All rights reserved.

import android.util.Base64

import java.nio.charset.StandardCharsets

object Base64Converter {

    private val LOG_TAG = "Base64Converter"

    fun base64DecodeToString(inData: String): String {
        return String(Base64.decode(inData.toByteArray(), Base64.DEFAULT), StandardCharsets.UTF_8)
    }

    fun encodeToBase64String(inData: ByteArray): String {
        return Base64.encodeToString(inData, Base64.NO_WRAP)
    }

    fun encodeToBase64(inData: ByteArray): ByteArray {
        return Base64.encode(inData, Base64.NO_WRAP)
    }
}
