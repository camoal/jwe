package com.camoal.jwe

import java.security.Key
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec


internal open class JweHelper {

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

    fun getCompactSerialization(jwe: String): List<String> {
        val compactSerialization = jwe.split(".")
        if(compactSerialization.size != 5) {
            throw IllegalArgumentException()
        }
        return compactSerialization
    }
}