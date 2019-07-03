package by.praviloffevg.cryptolib.rsa

import android.content.Context
import io.reactivex.Completable
import io.reactivex.Observable
import io.reactivex.Single
import io.reactivex.schedulers.Schedulers
import java.security.PublicKey

// Created by Yauheni Pravilau on 12.03.2019.
// Copyright (c) 2019 . All rights reserved.

object RsaRxJavaWrapper {

    private val computationScheduler = Schedulers.computation()

    fun getRsaInstance(context: Context, keyProperties: KeyProperties): Observable<RsaProvider> {
        return Observable.just<RsaProvider>(RsaProvider(context, keyProperties))
            .subscribeOn(computationScheduler)
    }

    fun generateNewKey(rsaProvider: RsaProvider): Completable =
        Completable.fromAction { Single.just(rsaProvider.createNewKeys()) }
            .subscribeOn(computationScheduler)

    fun deleteKeys(rsaProvider: RsaProvider): Completable =
        Completable.fromAction { Single.just(rsaProvider.deleteKey()) }
            .subscribeOn(computationScheduler)

    fun getPublicKey(rsaProvider: RsaProvider): Single<PublicKey> =
        Single.just(rsaProvider.getPublicKey())
            .subscribeOn(computationScheduler)

    fun isKeyExpired(rsaProvider: RsaProvider): Single<Boolean> =
        Single.just(rsaProvider.isKeyExpired())
            .subscribeOn(computationScheduler)

    fun encrypt(rsaProvider: RsaProvider, messageToEncrypt: String): Single<String> =
            Single.just(rsaProvider.encrypt(messageToEncrypt))
                .subscribeOn(computationScheduler)

    fun encryptWithProvidedPublicKey(rsaProvider: RsaProvider,
                                     messageToEncrypt: String,
                                     publicKey: PublicKey): Single<String> =
        Single.just(rsaProvider.encryptWithProvidedPublicKey(messageToEncrypt, publicKey))
            .subscribeOn(computationScheduler)

    fun decrypt(rsaProvider: RsaProvider,decryptedMessage: String): Single<String> =
            Single.just(rsaProvider.decrypt(decryptedMessage))
                .subscribeOn(computationScheduler)
}
