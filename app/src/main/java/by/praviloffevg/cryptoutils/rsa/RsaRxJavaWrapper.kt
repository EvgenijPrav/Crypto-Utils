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
    ): Observable<out Rsa> =
        Observable.just(RsaProvider(context, keyProperties))
            .subscribeOn(scheduler)

    @WorkerThread
    fun generateNewKeyPair(
        rsa: Rsa,
        scheduler: Scheduler = Schedulers.computation()
    ): Completable =
        Completable.fromAction { Single.just(rsa.createNewKeys()) }
            .subscribeOn(scheduler)

    @WorkerThread
    fun deleteKeys(rsa: Rsa, scheduler: Scheduler = Schedulers.computation())
            : Completable =
        Completable.fromAction { Single.just(rsa.deleteKey()) }
            .subscribeOn(scheduler)

    @WorkerThread
    fun getPublicKey(rsa: Rsa, scheduler: Scheduler = Schedulers.computation())
            : Single<PublicKey> =
        Single.just(rsa.getPublicKey())
            .subscribeOn(scheduler)

    @WorkerThread
    fun isKeyExpired(rsa: Rsa, scheduler: Scheduler = Schedulers.computation())
            : Single<Boolean> =
        Single.just(rsa.isKeyExpired())
            .subscribeOn(scheduler)

    @WorkerThread
    fun encrypt(
        rsa: Rsa,
        messageToEncrypt: String,
        scheduler: Scheduler = Schedulers.computation()
    ): Single<String> =
        Single.just(rsa.encrypt(messageToEncrypt))
            .subscribeOn(scheduler)

    @WorkerThread
    fun encryptWithProvidedPublicKey(
        rsa: Rsa,
        messageToEncrypt: String,
        publicKey: PublicKey,
        scheduler: Scheduler = Schedulers.computation()
    ): Single<String> =
        Single.just(rsa.encryptWithProvidedPublicKey(messageToEncrypt, publicKey))
            .subscribeOn(scheduler)

    @WorkerThread
    fun decrypt(
        rsa: Rsa,
        decryptedMessage: String,
        scheduler: Scheduler = Schedulers.computation()
    ): Single<String> =
        Single.just(rsa.decrypt(decryptedMessage))
            .subscribeOn(scheduler)
}
