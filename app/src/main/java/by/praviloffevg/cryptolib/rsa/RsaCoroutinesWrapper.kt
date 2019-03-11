package by.praviloffevg.cryptolib.rsa

import android.content.Context
import androidx.annotation.WorkerThread
import kotlinx.coroutines.runBlocking
import java.io.IOException
import java.security.*
import javax.crypto.NoSuchPaddingException


// Created by Yauheni Pravilau on 11.03.2019.
// Copyright (c) 2019 . All rights reserved.

object RsaCoroutinesWrapper {

    @WorkerThread
    suspend fun getRsaInstance(context: Context, keyProperties: KeyProperties): RsaProvider = runBlocking {
        RsaProvider(context, keyProperties)
    }

    @WorkerThread
    suspend fun generateNewKey(rsaProvider: RsaProvider) = runBlocking {
        rsaProvider.createNewKeys()
    }

    @WorkerThread
    suspend fun deleteKeys(rsaProvider: RsaProvider) = runBlocking {
        rsaProvider.deleteKey()
    }

    @Throws(
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        KeyStoreException::class
    )
    fun getPublicKey(rsaProvider: RsaProvider): PublicKey = rsaProvider.getPublicKey()

    @Throws(KeyValidationException::class)
    fun isKeyExpired(rsaProvider: RsaProvider): Boolean = rsaProvider.isKeyExpired()

    @WorkerThread
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
    suspend fun encrypt(rsaProvider: RsaProvider, messageToEncrypt: String): String = runBlocking {
        rsaProvider.encrypt(messageToEncrypt)
    }

    @WorkerThread
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
    suspend fun decrypt(rsaProvider: RsaProvider,decryptedMessage: String): String = runBlocking {
        rsaProvider.decrypt(decryptedMessage)
    }

}