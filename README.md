[![](https://jitpack.io/v/EvgenijPrav/Crypto-Utils.svg)](https://jitpack.io/#EvgenijPrav/Crypto-Utils) [![CircleCI](https://circleci.com/gh/EvgenijPrav/Crypto-Utils.svg?style=svg)](https://circleci.com/gh/EvgenijPrav/Crypto-Utils) [![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
# Crypto-Utils
Crypto-Utils is a tiny library to encrypt and decrypt your data with AES and RSA algorithms and to calculate hash values.

## Installation

Add Jitpack to your project build.gralde file
      
      allprojects {
		repositories {
			...
			maven { url 'https://jitpack.io' }
		}
	}
}

Then add this dependency to your app build.gradle file.

      dependencies {
	        implementation 'com.github.EvgenijPrav:Crypto-Utils:latest-release'
	}
  
## Usage

### Hash
`HashUtil` class contains the only method to calculate hash: `fun getHash(input: String, algorithm: Algorithms): String`.
`Algorithm` class contains supported hash algorithms (SHA1, SHA-224, SHA-256, SHA-384, SHA-512, MD5).

### AES
`AES` package allows you to encrypt your data using 2 modes: `ECB` and `CBC`.
If `CBC` is initialized without intialization vector (iv parameter in the constructor), it will work as `ECB`.
Both classes require `ByteKeyGenerator` as a constructor prameter. To create it's instance you should specify `key specification` and `salt` (not mandatory parameter).
Supported key specifications are: AES-128, AES-192 and AES-256.
If `salt` is not provided, `ByteKeyGenerator` will use dafault salt.

### RSA
`RsaProvider` class allows you to generate a key pair (private and public keys) to secure your data. Private key will be stored in Android keystore.
Steps:
* Create `KeyValidationProperties` instance:
It is used to determine how long the key should be valid. If the key is expired, it should be deleted and generated new one.
* Create `KeyProperties` instance:
It will allow to identify key owner.
* Finally, create `RsaProvider` instance by passing `Context` and created `KeyProperties` instance.

##### Basic operations
* `isKeyExpired()` - checks, if the key is expired based on `KeyValidationProperties` used on creation step.
* `createNewKeys()`- is used to enforce new key pair generation. Please note that when `RsaProvider` instance constructor is called, new key pair instance is generated.
* `fun encrypt(messageToEncrypt: String): String` - is used to encrypt data using generated public key (which is also stored in the keystore).
* `fun encryptWithProvidedPublicKey(messageToEncrypt: String, publicKey: PublicKey): String` - is used to encrypt data using provided public key.
* `fun getPublicKey(): PublicKey` - is used to fetch stored public key.
* `fun decrypt(decryptedMessage: String): String` - is used to decrypt data using private key from the keystore.
* `fun deleteKey()` - is used to delete key pair. May be used if the keys are expired or have been compromised.
##### Important
RSA related operations may reqiere a lot of time to execute, don't perform them on the main thread. To avoid using on the main thread presented `RsaRxJavaWrapper` class. Using this class you should pass `Scheduler` it should be subscribed on (default value is `Schedulers.computation()`)

## License

Copyright 2019 Yauheni Pravilau

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
         
      http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
