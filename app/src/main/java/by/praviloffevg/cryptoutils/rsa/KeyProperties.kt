package by.praviloffevg.cryptoutils.rsa

data class KeyProperties(
    val keyAlias: String,
    val keyOwnerName: String,
    val keyOrganizationName: String,
    val keyValidationProperties: KeyValidationProperties
)
