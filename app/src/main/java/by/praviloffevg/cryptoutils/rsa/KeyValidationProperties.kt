package by.praviloffevg.cryptoutils.rsa

import java.util.Calendar

data class KeyValidationProperties(
    val keyDurationPeriod: KeyDurationPeriod,
    val durationAmount: Int
) {
    enum class KeyDurationPeriod(val period: Int) {
        YEAR(Calendar.YEAR),
        MONTH(Calendar.MONTH),
        DAY(Calendar.DATE),
        HOUR(Calendar.HOUR),
        MINUTE(Calendar.MINUTE),
        SECOND(Calendar.SECOND),
        MILLISECOND(Calendar.MILLISECOND)
    }
}
