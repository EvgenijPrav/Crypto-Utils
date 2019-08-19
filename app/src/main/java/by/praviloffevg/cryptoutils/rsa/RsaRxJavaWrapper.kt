package by.praviloffevg.cryptoutils.rsa

import android.content.Context
import androidx.annotation.WorkerThread
import io.reactivex.Completable
import io.reactivex.Observable
import io.reactivex.Scheduler
import io.reactivex.Single
import io.reactivex.schedulers.Schedulers
import java.security.PrivateKey
import java.security.PublicKey

// Created by Yauheni Pravilau on 12.03.2019.
// Copyright (c) 2019 . All rights reserved.

object RsaRxJavaWrapper {

    /**
     * This method allows to create a new instance of [RsaProvider]
     * @param context [Context]
     * @param keyProperties properties that should be used while creation of the instance
     * @param scheduler Scheduler should be subscribed on
     * @return [Observable] with [RsaProvider] instance
     */
    @WorkerThread
    fun getRsaInstance(
        context: Context,
        keyProperties: KeyProperties,
        scheduler: Scheduler = Schedulers.computation()
    ): Observable<out Rsa> =
        Observable.just(RsaProvider(context, keyProperties))
            .subscribeOn(scheduler)

    /**
     * This method allows to generate new keys
     * @param rsa [Rsa] instance
     * @param scheduler Scheduler should be subscribed on
     * @return [Completable] with the result of method invocation
     */
    @WorkerThread
    fun generateNewKeyPair(
        rsa: Rsa,
        scheduler: Scheduler = Schedulers.computation()
    ): Completable =
        Completable.fromAction { Single.just(rsa.createNewKeys()) }
            .subscribeOn(scheduler)

    /**
     * This method allows to delete keys from the Android KeyStore
     * @param rsa [Rsa] instance
     * @param scheduler Scheduler should be subscribed on
     * @return [Completable] with the result of method invocation
     */
    @WorkerThread
    fun deleteKeys(rsa: Rsa, scheduler: Scheduler = Schedulers.computation())
            : Completable =
        Completable.fromAction { Single.just(rsa.deleteKeys()) }
            .subscribeOn(scheduler)

    /**
     * This method allows to fetch [PublicKey]
     * @param rsa [Rsa] instance
     * @param scheduler Scheduler should be subscribed on
     * @return [Single] with [PublicKey] instance
     */
    @WorkerThread
    fun getPublicKey(rsa: Rsa, scheduler: Scheduler = Schedulers.computation())
            : Single<PublicKey> =
        Single.just(rsa.getPublicKey())
            .subscribeOn(scheduler)

    /**
     * This method allows to check if the keys are expired
     * @param rsa [Rsa] instance
     * @param scheduler Scheduler should be subscribed on
     * @return [Single] with the [Boolean] value shows is the keys have been expired
     */
    @WorkerThread
    fun isKeyExpired(rsa: Rsa, scheduler: Scheduler = Schedulers.computation())
            : Single<Boolean> =
        Single.just(rsa.isKeyExpired())
            .subscribeOn(scheduler)

    /**
     * This method allows to encrypt data
     * @param rsa [Rsa] instance
     * @param messageToEncrypt message to encrypt
     * @param scheduler Scheduler should be subscribed on
     * @return [Single] with encrypted data
     */
    @WorkerThread
    fun encrypt(
        rsa: Rsa,
        messageToEncrypt: ByteArray,
        scheduler: Scheduler = Schedulers.computation()
    ): Single<ByteArray> =
        Single.just(rsa.encrypt(messageToEncrypt))
            .subscribeOn(scheduler)

    /**
     * This method allows to encrypt data using provided [PublicKey]
     * @param rsa [Rsa] instance
     * @param messageToEncrypt message to encrypt
     * @param publicKey [PublicKey]
     * @param scheduler Scheduler should be subscribed on
     * @return [Single] with encrypted data
     */
    @WorkerThread
    fun encryptWithProvidedPublicKey(
        rsa: Rsa,
        messageToEncrypt: ByteArray,
        publicKey: PublicKey,
        scheduler: Scheduler = Schedulers.computation()
    ): Single<ByteArray> =
        Single.just(rsa.encryptWithProvidedPublicKey(messageToEncrypt, publicKey))
            .subscribeOn(scheduler)

    /**
     * This method allows to decrypt data using stored [PrivateKey]
     * @param rsa [Rsa] instance
     * @param messageToDecrypt message to decrypt
     * @param scheduler Scheduler should be subscribed on
     * @return [Single] with decrypted data
     */
    @WorkerThread
    fun decrypt(
        rsa: Rsa,
        messageToDecrypt: ByteArray,
        scheduler: Scheduler = Schedulers.computation()
    ): Single<ByteArray> =
        Single.just(rsa.decrypt(messageToDecrypt))
            .subscribeOn(scheduler)
}
