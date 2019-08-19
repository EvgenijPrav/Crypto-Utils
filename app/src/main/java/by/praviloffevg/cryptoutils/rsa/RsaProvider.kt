package by.praviloffevg.cryptoutils.rsa

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.NoSuchPaddingException
import javax.security.auth.x500.X500Principal

class RsaProvider(private val context: Context, private val keyProperties: KeyProperties) : Rsa {

    private companion object {
        private const val TAG = "RsaProvider"
        private const val CIPHER_TYPE = "RSA/ECB/PKCS1Padding"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val RSA_ALGORITHM = "RSA"
    }

    private val keyStore: KeyStore

    init {
        keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        initializeKeyStore()
    }

    private val cipherProvider: String = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
        "AndroidOpenSSL"
    } else {
        "AndroidKeyStoreBCWorkaround"
    }

    private fun initializeKeyStore() {
        keyStore.load(null)
        checkExistingKeys()
    }

    private fun checkExistingKeys() {
        if (!isKeyExist()) {
            Log.d(TAG, "Key not found, creating new")
            createNewKeys()
        } else {
            Log.d(TAG, "Key found")
        }
    }

    private fun isKeyExist() = keyStore.containsAlias(keyProperties.keyAlias)

    /**
     * This method allows to check if the key is expired
     * @return is the key has been expired
     * @exception KeyValidationException - if the key is not found
     */
    @Throws(KeyValidationException::class)
    override fun isKeyExpired(): Boolean {
        if (!isKeyExist()) {
            throw KeyValidationException(
                KeyValidationException.ExceptionCode.KEY_NOT_FOUND,
                "Key not found"
            )
        }
        val certificate = keyStore.getCertificate(keyProperties.keyAlias) as X509Certificate
        val expirationDate = certificate.notAfter
        val creationDate = certificate.notBefore

        return expirationDate.time < System.currentTimeMillis()
                || creationDate.time > System.currentTimeMillis()
    }

    /**
     * This method allows to generate new keys
     */
    override fun createNewKeys() {
        Log.d(TAG, "Creating new key")
        val x500Name = "CN=${keyProperties.keyOwnerName}, O=${keyProperties.keyOrganizationName}"
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance()
        endDate.add(
            keyProperties.keyValidationProperties.keyDurationPeriod.period,
            keyProperties.keyValidationProperties.durationAmount
        )
        val keyPairGeneratorSpec = KeyPairGeneratorSpec.Builder(context)
            .setAlias(keyProperties.keyAlias)
            .setSubject(X500Principal(x500Name))
            .setSerialNumber(BigInteger.ONE)
            .setStartDate(startDate.time)
            .setEndDate(endDate.time)
            .build()
        val generator = KeyPairGenerator.getInstance(RSA_ALGORITHM, KEYSTORE_PROVIDER)
        generator.initialize(keyPairGeneratorSpec)
        generator.generateKeyPair()
    }

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
    override fun encrypt(messageToEncrypt: ByteArray): ByteArray {
        if (isKeyExpired()) {
            throw KeyValidationException(
                KeyValidationException.ExceptionCode.KEY_EXPIRED,
                "Key expired"
            )
        }
        val cipher: Cipher = Cipher.getInstance(CIPHER_TYPE, cipherProvider)
        val publicKey = getPublicKey()
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, cipher)
        cipherOutputStream.write(messageToEncrypt)
        cipherOutputStream.close()

        return outputStream.toByteArray()
    }

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
    override fun encryptWithProvidedPublicKey(
        messageToEncrypt: ByteArray,
        publicKey: PublicKey
    ): ByteArray {
        if (isKeyExpired()) {
            throw KeyValidationException(
                KeyValidationException.ExceptionCode.KEY_EXPIRED,
                "Key expired"
            )
        }
        val cipher: Cipher = Cipher.getInstance(CIPHER_TYPE, cipherProvider)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, cipher)
        cipherOutputStream.write(messageToEncrypt)
        cipherOutputStream.close()

        return outputStream.toByteArray()
    }

    /**
     * This method allows to fetch [PublicKey]
     * @return public key
     */
    @Throws(
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        KeyStoreException::class
    )
    override fun getPublicKey(): PublicKey {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            keyStore.getCertificate(keyProperties.keyAlias).publicKey
        } else {
            val privateKeyEntry = keyStore.getEntry(keyProperties.keyAlias, null)
                    as KeyStore.PrivateKeyEntry
            privateKeyEntry.certificate.publicKey
        }
    }

    /**
     * This method allows to decrypt data using stored [PrivateKey]
     * @param messageToDecrypt message to decrypt
     * @return decrypted data
     */
    @Suppress("LongMethod")
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
    override fun decrypt(messageToDecrypt: ByteArray): ByteArray {
        if (isKeyExpired()) {
            throw KeyValidationException(
                KeyValidationException.ExceptionCode.KEY_EXPIRED,
                "Key expired"
            )
        }
        val cipher: Cipher = Cipher.getInstance(CIPHER_TYPE, cipherProvider)
        val privateKey = getPrivateKey()
        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        val byteArrayInputStream = ByteArrayInputStream(messageToDecrypt)
        val cipherInputStream = CipherInputStream(byteArrayInputStream, cipher)
        val values = ArrayList<Byte>()
        var nextBytes: Int
        while (cipherInputStream.read()
                .let {
                    nextBytes = it
                    it != -1
                }
        ) {
            values.add(nextBytes.toByte())
        }
        val bytes = ByteArray(values.size)
        for (i in bytes.indices) {
            bytes[i] = values[i]
        }
        return bytes
    }

    @Throws(
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        KeyStoreException::class
    )
    private fun getPrivateKey(): PrivateKey {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            keyStore.getKey(keyProperties.keyAlias, null)
                    as PrivateKey
        } else {
            val privateKeyEntry = keyStore.getEntry(keyProperties.keyAlias, null)
                    as KeyStore.PrivateKeyEntry
            privateKeyEntry.privateKey
        }
    }

    /**
     * This method allows to delete keys from the Android KeyStore
     */
    override fun deleteKeys() {
        if (isKeyExist()) {
            Log.d(TAG, "Key exists, deleting the key")
            keyStore.deleteEntry(keyProperties.keyAlias)
        }
    }
}
