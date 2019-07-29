package by.praviloffevg.cryptoutils.rsa

import android.content.Context
import androidx.annotation.WorkerThread
import io.reactivex.Completable
import io.reactivex.Observable
import io.reactivex.Scheduler
import io.reactivex.Single
import io.reactivex.schedulers.Schedulers
import java.security.PublicKey

// Created by Yauheni Pravilau on 12.03.2019.
// Copyright (c) 2019 . All rights reserved.

object RsaRxJavaWrapper {

    @WorkerThread
    fun getRsaInstance(
        context: Context,
        keyProperties: KeyProperties,
        scheduler: Scheduler = Schedulers.computation()
    ): Observable<RsaProvider> =
        Observable.just(RsaProvider(context, keyProperties))
            .subscribeOn(scheduler)


    @WorkerThread
    fun generateNewKeyPair(
        rsaProvider: RsaProvider,
        scheduler: Scheduler = Schedulers.computation()
    ): Completable =
        Completable.fromAction { Single.just(rsaProvider.createNewKeys()) }
            .subscribeOn(scheduler)

    @WorkerThread
    fun deleteKeys(rsaProvider: RsaProvider, scheduler: Scheduler = Schedulers.computation())
            : Completable =
        Completable.fromAction { Single.just(rsaProvider.deleteKey()) }
            .subscribeOn(scheduler)

    @WorkerThread
    fun getPublicKey(rsaProvider: RsaProvider, scheduler: Scheduler = Schedulers.computation())
            : Single<PublicKey> =
        Single.just(rsaProvider.getPublicKey())
            .subscribeOn(scheduler)

    @WorkerThread
    fun isKeyExpired(rsaProvider: RsaProvider, scheduler: Scheduler = Schedulers.computation())
            : Single<Boolean> =
        Single.just(rsaProvider.isKeyExpired())
            .subscribeOn(scheduler)

    @WorkerThread
    fun encrypt(
        rsaProvider: RsaProvider,
        messageToEncrypt: String,
        scheduler: Scheduler = Schedulers.computation()
    ): Single<String> =
        Single.just(rsaProvider.encrypt(messageToEncrypt))
            .subscribeOn(scheduler)

    @WorkerThread
    fun encryptWithProvidedPublicKey(
        rsaProvider: RsaProvider,
        messageToEncrypt: String,
        publicKey: PublicKey,
        scheduler: Scheduler = Schedulers.computation()
    ): Single<String> =
        Single.just(rsaProvider.encryptWithProvidedPublicKey(messageToEncrypt, publicKey))
            .subscribeOn(scheduler)

    @WorkerThread
    fun decrypt(
        rsaProvider: RsaProvider,
        decryptedMessage: String,
        scheduler: Scheduler = Schedulers.computation()
    ): Single<String> =
        Single.just(rsaProvider.decrypt(decryptedMessage))
            .subscribeOn(scheduler)
}
