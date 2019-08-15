package by.praviloffevg.cryptoutils.rsa

import java.io.IOException
import java.security.*
import javax.crypto.NoSuchPaddingException

interface Rsa {

    @Throws(KeyValidationException::class)
    fun isKeyExpired(): Boolean

    fun createNewKeys()

    @Throws(
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        KeyStoreException::class,
        UnrecoverableEntryException::class,
        InvalidKeyException::class,
        IOException::class,
        KeyValidationException::class
    )
    fun encrypt(messageToEncrypt: String): String

    @Throws(
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        KeyStoreException::class,
        UnrecoverableEntryException::class,
        InvalidKeyException::class,
        IOException::class,
        KeyValidationException::class
    )
    fun encryptWithProvidedPublicKey(messageToEncrypt: String, publicKey: PublicKey): String

    @Throws(
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        KeyStoreException::class
    )
    fun getPublicKey(): PublicKey

    @Throws(
        IOException::class,
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidKeyException::class,
        KeyStoreException::class,
        UnrecoverableEntryException::class,
        KeyValidationException::class
    )
    fun decrypt(decryptedMessage: String): String

    @Throws(
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        KeyStoreException::class
    )
    fun getPrivateKey(): PrivateKey

    fun deleteKey()
}
