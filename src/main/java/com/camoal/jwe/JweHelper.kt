package com.camoal.jwe

import android.util.Base64
import java.security.Key
import java.security.MessageDigest
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec


internal interface JweHelper {

    fun getSymmetricCipher(key: ByteArray, cipherMode: Int, iv: ByteArray): Cipher {
        val secretKeySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, iv)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(cipherMode, secretKeySpec, gcmSpec)
        return cipher
    }

    fun getAsymetricCipher(key: Key, cipherMode: Int, algorithm: Algorithm): Cipher {
        return when(algorithm) {
            Algorithm.RSA_OAEP -> {
                Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
                    .apply {
                        init(cipherMode, key)
                    }
            }
            Algorithm.RSA_OAEP_256 -> {
                Cipher.getInstance("RSA/ECB/OAEPPadding")
                    .apply {
                        init(cipherMode, key, OAEPParameterSpec(
                            "SHA-256",
                            "MGF1",
                            MGF1ParameterSpec.SHA256,
                            PSource.PSpecified.DEFAULT)
                        )
                    }
            }
        }
    }

    fun computeCipher(cipher: Cipher, data: ByteArray, add: ByteArray? = null): ByteArray {
        add?.let {
            cipher.updateAAD(it)
        }
        return cipher.doFinal(data)
    }

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

    fun String.parse(): List<String> {
        val list = this.split(".")
        if(list.size != 5) {
            throw IllegalArgumentException()
        }
        return list
    }
}