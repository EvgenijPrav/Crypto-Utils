package by.praviloffevg.cryptolib


// Created by Yauheni Pravilau on 09.02.2019.
// Copyright (c) 2019 . All rights reserved.

enum class AesKeySpecification(internal val length: Int) {
    AES128(128),
    AES192(192),
    AES256(256)
}