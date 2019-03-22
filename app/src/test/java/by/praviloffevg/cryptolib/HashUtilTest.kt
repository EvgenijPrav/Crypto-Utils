package by.praviloffevg.cryptolib

import assertk.assert
import assertk.assertions.isEqualTo
import junitparams.JUnitParamsRunner
import junitparams.Parameters
import org.junit.Test
import org.junit.runner.RunWith


// Created by Yauheni Pravilau on 03.02.2019.
// Copyright (c) 2019 . All rights reserved.

@Suppress("DEPRECATION")
@RunWith(JUnitParamsRunner::class)
class HashUtilTest {

    private val hashUtil = HashUtil

    @Test
    @Parameters(method = "getHashes")
    fun `should return correct hash`(inputParam: String, expectedParam: String, algorithm: Algorithms) {
        assert(hashUtil.getHash(inputParam, algorithm)).isEqualTo(expectedParam)
    }

    @Test
    @Parameters(method = "getLength")
    fun `should return correct length`(algorithm: Algorithms, length: Int) {
        val inputParam = "Test"
        val hashedValue = hashUtil.getHash(inputParam, algorithm)
        assert(hashedValue.length).isEqualTo(length)
    }

    @Test
    @Parameters(method = "getAlgorithms")
    fun `should return the same values when getting hash given called second time`(algorithm: Algorithms) {
        val inputParam = "input param"
        val firstHash = hashUtil.getHash(inputParam, algorithm)

        val secondHash = hashUtil.getHash(inputParam, algorithm)

        assert(firstHash).isEqualTo(secondHash)
    }

    fun getHashes() = arrayOf(
        arrayOf(
            "First",
            "916a78d701ded328cd66da58a97ef8cd28a99e84",
            Algorithms.SHA1
        ),
        arrayOf(
            "Quick setup",
            "24cc2440fd1b49aaf1c5a8958c6de61e1529c18a",
            Algorithms.SHA1
        ),
        arrayOf(
            "Empty",
            "3159fe421b3221381b3c778dc1c3c26e4540be37",
            Algorithms.SHA1
        ),
        arrayOf(
            "Don't miss out on any of 2018's biggest innovations. Take a look back at some of the year's highlights.",
            "7588d5e52ab9e653388d1095be90b3c4caa08c3d",
            Algorithms.SHA1
        ),
        arrayOf(
            "Android's new app publishing format means a smaller app for your users and a more-efficient release process for you. Also deliver dynamic features on demand with modularization and increase discovery with Google Play Instant.",
            "58dbf460692149ab98f4d3884b3d3438bddb9327",
            Algorithms.SHA1
        ),

        arrayOf(
            "First",
            "1272e464bcf661f9c693bb23e90d62a6cfe4f989582b1cb875473e53",
            Algorithms.SHA_224
        ),
        arrayOf(
            "Quick setup",
            "0ced5e22661b2c7aaedc1c090bc3f249e873bed6ba06430c0840f6ec",
            Algorithms.SHA_224
        ),
        arrayOf(
            "Empty",
            "92d2d0e4079627c2b3ed27bc4459937ccb9f095d170b2bde781e9e7e",
            Algorithms.SHA_224
        ),
        arrayOf(
            "Don't miss out on any of 2018's biggest innovations. Take a look back at some of the year's highlights.",
            "d22e3b75997681de56cc24657db79d6a67ac179405f4b6251df216b9",
            Algorithms.SHA_224
        ),
        arrayOf(
            "Android's new app publishing format means a smaller app for your users and a more-efficient release process for you. Also deliver dynamic features on demand with modularization and increase discovery with Google Play Instant.",
            "353a5a5d1105dfcf98cf1549912b7b4af31a936b7c77de5b3b3cae2c",
            Algorithms.SHA_224
        ),


        arrayOf(
            "First",
            "a151ceb1711aad529a7704248f03333990022ebbfa07a7f04c004d70c167919f",
            Algorithms.SHA_256
        ),
        arrayOf(
            "Quick setup",
            "7cf66ba7dbbb0f48cbb2afe9543918eaf9480807061c1a77d95f134003b5f9d6",
            Algorithms.SHA_256
        ),
        arrayOf(
            "Empty",
            "c6c094bc0054f9cbe34102ff49f86b3928b5ac09f3d2ac87e170d0500675921f",
            Algorithms.SHA_256
        ),
        arrayOf(
            "Don't miss out on any of 2018's biggest innovations. Take a look back at some of the year's highlights.",
            "ad9c48e93f1bdc9059c0683cdf550d920b6db39375989f283920b92ee8572f55",
            Algorithms.SHA_256
        ),
        arrayOf(
            "Android's new app publishing format means a smaller app for your users and a more-efficient release process for you. Also deliver dynamic features on demand with modularization and increase discovery with Google Play Instant.",
            "52b0aed0ce473d3d0b41af63f1fb23c9ee99b467b58d026c4c3e53c169cac527",
            Algorithms.SHA_256
        ),

        arrayOf(
            "First",
            "de21ccb3e0174edef550563c2ab7f25115a2d28c2bd72ec4c5dff88bd83b02c0f2df2735f36016d8a22103b6c48cbd06",
            Algorithms.SHA_384
        ),
        arrayOf(
            "Quick setup",
            "f29ba082b413415c17e0d7493ee4681154f5123b9a3a3c2d8d19615738215afdc9df5cb7d693bdedf5d3b91e0e3da290",
            Algorithms.SHA_384
        ),
        arrayOf(
            "Empty",
            "a3878693f6bd6cacb03e271b31a38050d7227904919801e69fa3496bb2a3e1cb163856b4c9bc5b74c3d988e7389ef906",
            Algorithms.SHA_384
        ),
        arrayOf(
            "Don't miss out on any of 2018's biggest innovations. Take a look back at some of the year's highlights.",
            "998b5ab691fd85a49728711134802ece1b636296a81401c2e1e50d286fcd82a09f77fafd48f40521a2763ac675cfc4a7",
            Algorithms.SHA_384
        ),
        arrayOf(
            "Android's new app publishing format means a smaller app for your users and a more-efficient release process for you. Also deliver dynamic features on demand with modularization and increase discovery with Google Play Instant.",
            "6872a4dda9b836f16cb16ad8242af6d12740247d1a8f0a0584d2cadfc425df76c16c80e0b06e2418b23963393fc7b4cf",
            Algorithms.SHA_384
        ),

        arrayOf(
            "First",
            "4b8e5aa1cd6cf2441e84257416a62e2fa5da4fe2864943bd129f797000e9b79ce37c55fd8a7092999630dbd75811ad50ef8fecd5e56449a32857fb4d285e2ad3",
            Algorithms.SHA_512
        ),
        arrayOf(
            "Quick setup",
            "f7d777bbc93dedf576aa5c902a9f13fd19a47b695923264cf371e40b081fdf45720f26d7bcfb7b31b2f3095385c80c3b7d9b7dee6009dd315e6a1c84dec2056d",
            Algorithms.SHA_512
        ),
        arrayOf(
            "Empty",
            "f918671febc52ce97d7233b92c256292d74450fb6d922cbdf001aaffc7a56ade4582cabd81f3b8f6f19e7f732865e43a4d60fc8f49521f3f35df700c31490ae3",
            Algorithms.SHA_512
        ),
        arrayOf(
            "Don't miss out on any of 2018's biggest innovations. Take a look back at some of the year's highlights.",
            "74a97ced458c6c1934516fa1ded81cfb03198d4a0320114df2d2cdc63e10af4ad80f312065a01dd09a6064eeacf5a5a84f9f72dd4460bdf08d7b2b10a8a140e5",
            Algorithms.SHA_512
        ),
        arrayOf(
            "Android's new app publishing format means a smaller app for your users and a more-efficient release process for you. Also deliver dynamic features on demand with modularization and increase discovery with Google Play Instant.",
            "3ff63d1b457f35e8477acf94d374ebc27aa17087a2f7f51ec5fccbe32cb8c0b7febb54d133d274416709240c5e9a889a53aeb6cd6574ed40dee4d43aefc88c70",
            Algorithms.SHA_512
        ),

        arrayOf(
            "First",
            "7fb55ed0b7a30342ba6da306428cae04",
            Algorithms.MD5
        ),
        arrayOf(
            "Quick setup",
            "07644de2851ce746d359026d687f0172",
            Algorithms.MD5
        ),
        arrayOf(
            "Empty",
            "ce2c8aed9c2fa0cfbed56cbda4d8bf07",
            Algorithms.MD5
        ),
        arrayOf(
            "Don't miss out on any of 2018's biggest innovations. Take a look back at some of the year's highlights.",
            "60962a0e790aa45e1ad1fe74192a93e3",
            Algorithms.MD5
        ),
        arrayOf(
            "Android's new app publishing format means a smaller app for your users and a more-efficient release process for you. Also deliver dynamic features on demand with modularization and increase discovery with Google Play Instant.",
            "e40bcdb9f4dd38f663e621fdb25ce38b",
            Algorithms.MD5
        )
    )

    fun getLength() = arrayOf(
        arrayOf(Algorithms.SHA1, 40),
        arrayOf(Algorithms.SHA_224, 56),
        arrayOf(Algorithms.SHA_256, 64),
        arrayOf(Algorithms.SHA_384, 96),
        arrayOf(Algorithms.SHA_512, 128),
        arrayOf(Algorithms.MD5, 32)
    )

    fun getAlgorithms() = arrayOf(
        arrayOf(Algorithms.SHA1),
        arrayOf(Algorithms.SHA_224),
        arrayOf(Algorithms.SHA_256),
        arrayOf(Algorithms.SHA_384),
        arrayOf(Algorithms.SHA_512),
        arrayOf(Algorithms.MD5)
    )

}