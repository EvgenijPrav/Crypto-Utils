package by.praviloffevg.cryptolib.rsa

import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.util.Base64
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.cert.X509Certificate
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.NoSuchPaddingException
import javax.security.auth.x500.X500Principal

class RsaProvider(private val context: Context, private val keyProperties: KeyProperties) {

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

    fun isKeyExpired(): Boolean {
        val certificate = keyStore.getCertificate(keyProperties.keyAlias) as X509Certificate
        val expirationDate = certificate.notAfter
        val creationDate = certificate.notBefore

        return expirationDate.time < System.currentTimeMillis() || creationDate.time > System.currentTimeMillis()
    }

    fun createNewKeys() {
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

    @Throws(
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        KeyStoreException::class,
        UnrecoverableEntryException::class,
        InvalidKeyException::class,
        IOException::class,
        CertificateIsNotValidException::class
    )
    fun encrypt(messageToEncrypt: String): String {
        if (isKeyExpired()) {
            throw CertificateIsNotValidException("Key expired")
        }
        val cipher: Cipher
        try {
            val publicKey = getPublicKey()
            cipher = Cipher.getInstance(CIPHER_TYPE, cipherProvider)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        } catch (e: KeyStoreException) {
            throw KeyStoreException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw NoSuchAlgorithmException(e)
        } catch (e: UnrecoverableEntryException) {
            throw UnrecoverableEntryException(e.message)
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException(e)
        } catch (e: NoSuchPaddingException) {
            throw NoSuchPaddingException(e.message)
        } catch (e: NoSuchProviderException) {
            throw NoSuchProviderException(e.message)
        }

        val outputStream = ByteArrayOutputStream()
        try {
            val cipherOutputStream = CipherOutputStream(outputStream, cipher)
            cipherOutputStream.write(messageToEncrypt.toByteArray(StandardCharsets.UTF_8))
            cipherOutputStream.close()
        } catch (e: IOException) {
            throw IOException(e)
        }

        val outputBytes = outputStream.toByteArray()
        return Base64.encodeToString(outputBytes, Base64.DEFAULT)
    }

    @Throws(
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        KeyStoreException::class
    )
    fun getPublicKey(): PublicKey {
        val publicKey: PublicKey
        try {
            publicKey = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                keyStore.getCertificate(keyProperties.keyAlias).publicKey
            } else {
                val privateKeyEntry = keyStore.getEntry(keyProperties.keyAlias, null)
                        as KeyStore.PrivateKeyEntry
                privateKeyEntry.certificate.publicKey
            }
        } catch (e: KeyStoreException) {
            throw KeyStoreException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw NoSuchAlgorithmException(e)
        } catch (e: UnrecoverableEntryException) {
            throw UnrecoverableEntryException(e.message)
        }
        return publicKey
    }

    @Throws(
        IOException::class,
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidKeyException::class,
        KeyStoreException::class,
        UnrecoverableEntryException::class,
        CertificateIsNotValidException::class
    )
    fun decrypt(decryptedMessage: String): String {
        if (isKeyExpired()) {
            throw CertificateIsNotValidException("Key expired")
        }
        val cipher: Cipher
        try {
            val privateKey = getPrivateKey()
            cipher = Cipher.getInstance(CIPHER_TYPE, cipherProvider)
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
        } catch (e: KeyStoreException) {
            throw KeyStoreException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw NoSuchAlgorithmException(e)
        } catch (e: UnrecoverableEntryException) {
            throw UnrecoverableEntryException(e.message)
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException(e)
        } catch (e: NoSuchPaddingException) {
            throw NoSuchPaddingException(e.message)
        } catch (e: NoSuchProviderException) {
            throw NoSuchProviderException(e.message)
        }

        val byteArrayInputStream = ByteArrayInputStream(Base64.decode(decryptedMessage, Base64.DEFAULT))
        val cipherInputStream = CipherInputStream(byteArrayInputStream, cipher)
        val values = ArrayList<Byte>()
        var nextBytes: Int
        try {
            while (cipherInputStream.read()
                    .let {
                        nextBytes = it
                        it != -1
                    }
            ) {
                values.add(nextBytes.toByte())
            }
        } catch (e: IOException) {
            throw IOException(e)
        }
        val bytes = ByteArray(values.size)
        for (i in bytes.indices) {
            bytes[i] = values[i]
        }

        return String(bytes, 0, bytes.size, StandardCharsets.UTF_8)
    }

    @Throws(
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        KeyStoreException::class
    )
    private fun getPrivateKey(): PrivateKey {
        val privateKey: PrivateKey
        try {
            privateKey = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                keyStore.getKey(keyProperties.keyAlias, null)
                        as PrivateKey
            } else {
                val privateKeyEntry = keyStore.getEntry(keyProperties.keyAlias, null)
                        as KeyStore.PrivateKeyEntry
                privateKeyEntry.privateKey
            }
        } catch (e: KeyStoreException) {
            throw KeyStoreException(e)
        } catch (e: NoSuchAlgorithmException) {
            throw NoSuchAlgorithmException(e)
        } catch (e: UnrecoverableEntryException) {
            throw UnrecoverableEntryException(e.message)
        }

        return privateKey
    }

    fun deleteKey() {
        if (isKeyExist()) {
            Log.d(TAG, "Key exists, deleting the key")
            keyStore.deleteEntry(keyProperties.keyAlias)
        }
    }
}