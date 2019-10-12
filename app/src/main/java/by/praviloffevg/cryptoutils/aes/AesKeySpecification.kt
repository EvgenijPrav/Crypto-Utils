package by.praviloffevg.cryptoutils.aes

enum class AesKeySpecification(internal val length: Int) {
    AES128(128),
    AES192(192),
    AES256(256)
}
