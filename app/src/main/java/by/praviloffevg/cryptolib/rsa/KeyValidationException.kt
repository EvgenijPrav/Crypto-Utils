package by.praviloffevg.cryptolib.rsa




class KeyValidationException (code: ExceptionCode ,message: String) : Exception(message) {
        enum class ExceptionCode {
        KEY_NOT_FOUND,
        KEY_EXPIRED
    }

}