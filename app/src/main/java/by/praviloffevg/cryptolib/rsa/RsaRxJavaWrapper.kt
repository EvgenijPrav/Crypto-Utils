package by.praviloffevg.cryptolib.rsa

import android.content.Context
import androidx.annotation.WorkerThread
import io.reactivex.Completable
import io.reactivex.Observable
import io.reactivex.Single
import io.reactivex.schedulers.Schedulers
import java.security.PublicKey

// Created by Yauheni Pravilau on 12.03.2019.
// Copyright (c) 2019 . All rights reserved.

object RsaRxJavaWrapper {

    @WorkerThread
    fun getRsaInstance(context: Context, keyProperties: KeyProperties): Observable<RsaProvider> {
        return Observable.just(RsaProvider(context, keyProperties))
            .subscribeOn(Schedulers.computation())
    }

    @WorkerThread
    fun generateNewKey(rsaProvider: RsaProvider): Completable =
        Completable.fromAction { Single.just(rsaProvider.createNewKeys()) }
            .subscribeOn(Schedulers.computation())

    @WorkerThread
    fun deleteKeys(rsaProvider: RsaProvider): Completable =
        Completable.fromAction { Single.just(rsaProvider.deleteKey()) }
            .subscribeOn(Schedulers.computation())

    @WorkerThread
    fun getPublicKey(rsaProvider: RsaProvider): Single<PublicKey> =
        Single.just(rsaProvider.getPublicKey())
            .subscribeOn(Schedulers.computation())

    @WorkerThread
    fun isKeyExpired(rsaProvider: RsaProvider): Single<Boolean> =
        Single.just(rsaProvider.isKeyExpired())
            .subscribeOn(Schedulers.computation())

    @WorkerThread
    fun encrypt(rsaProvider: RsaProvider, messageToEncrypt: String): Single<String> =
        Single.just(rsaProvider.encrypt(messageToEncrypt))
            .subscribeOn(Schedulers.computation())

    @WorkerThread
    fun encryptWithProvidedPublicKey(
        rsaProvider: RsaProvider,
        messageToEncrypt: String,
        publicKey: PublicKey
    ): Single<String> =
        Single.just(rsaProvider.encryptWithProvidedPublicKey(messageToEncrypt, publicKey))
            .subscribeOn(Schedulers.computation())

    @WorkerThread
    fun decrypt(rsaProvider: RsaProvider, decryptedMessage: String): Single<String> =
        Single.just(rsaProvider.decrypt(decryptedMessage))
            .subscribeOn(Schedulers.computation())
}
