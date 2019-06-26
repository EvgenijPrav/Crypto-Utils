package by.praviloffevg.cryptolib.rsa

import java.util.*

enum class KeyDurationPeriod(val period: Int) {
    YEAR(Calendar.YEAR),
    MONTH(Calendar.MONTH),
    DAY(Calendar.DATE),
    HOUR(Calendar.HOUR),
    MINUTE(Calendar.MINUTE),
    SECOND(Calendar.SECOND),
    MILLISECOND(Calendar.MILLISECOND)
}
