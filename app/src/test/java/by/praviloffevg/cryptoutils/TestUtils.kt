package by.praviloffevg.cryptoutils

object TestUtils {
    fun byteArrayOfInts(vararg ints: Int) = ByteArray(ints.size) { pos -> ints[pos].toByte() }
}