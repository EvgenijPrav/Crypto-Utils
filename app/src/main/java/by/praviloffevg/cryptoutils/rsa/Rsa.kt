package by.praviloffevg.cryptoutils.rsa

import java.io.IOException
import java.security.InvalidKeyException
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PublicKey
import java.security.UnrecoverableEntryException
import javax.crypto.NoSuchPaddingException

interface Rsa {

    /**
     * This method allows to check if the keys are expired
     * @return is the key has been expired
     * @exception KeyValidationException - if the key is not found
     */
    @Throws(KeyValidationException::class)
    fun isKeyExpired(): Boolean

    /**
     * This method allows to generate new keys
     */
    fun createNewKeys()

    /**
     * This method allows to encrypt data
     * @param messageToEncrypt message to encrypt
     * @return encrypted data
     */
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
    fun encrypt(messageToEncrypt: ByteArray): ByteArray

    /**
     * This method allows to encrypt data using [PublicKey]
     * @param messageToEncrypt message to encrypt
     * @param publicKey public key
     * @return encrypted data
     */
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
    fun encryptWithProvidedPublicKey(messageToEncrypt: ByteArray, publicKey: PublicKey): ByteArray

    /**
     * This method allows to fetch [PublicKey]
     * @return public key
     */
    @Throws(
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        KeyStoreException::class
    )
    fun getPublicKey(): PublicKey

    /**
     * This method allows to decrypt data using stored [PrivateKey]
     * @param messageToDecrypt message to decrypt
     * @return decrypted data
     */
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
    fun decrypt(messageToDecrypt: ByteArray): ByteArray

    /**
     * This method allows to delete keys from the Android KeyStore
     */
    fun deleteKeys()
}
