package by.praviloffevg.cryptolib.rsa

class KeyValidationException(val code: ExceptionCode, override val message: String) : Exception(message) {
    enum class ExceptionCode {
        KEY_NOT_FOUND,
        KEY_EXPIRED
    }
}
