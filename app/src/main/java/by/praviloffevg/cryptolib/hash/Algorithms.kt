package by.praviloffevg.cryptolib.hash

enum class Algorithms(val type: String) {
    SHA1("SHA1"),
    SHA_224("SHA-224"),
    SHA_256("SHA-256"),
    SHA_384("SHA-384"),
    SHA_512("SHA-512"),
    @Deprecated("Avoid using MD5 for hashing") MD5("MD5")
}
