package com.camoal.jwe

import android.util.Base64
import java.security.MessageDigest

fun ByteArray.toSha256(): ByteArray {
    val messageDigest = MessageDigest.getInstance("SHA-256")
    return messageDigest.digest(this)
}

fun ByteArray.toBase64(): String {
    return Base64.encodeToString(this,
        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}

fun String.fromBase64(): ByteArray {
    return Base64.decode(this,
        Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}