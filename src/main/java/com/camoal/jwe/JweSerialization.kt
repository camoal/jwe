package com.camoal.jwe

internal object JweSerialization {

    const val HEADER = 0
    const val ENCRYPTED_KEY = 1
    const val IV = 2
    const val CIPHER_TEXT = 3
    const val AUTHENTICATION_TAG = 4
}