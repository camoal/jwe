package com.camoal.jwe

import com.camoal.jwe.JweSerialization.AUTHENTICATION_TAG
import com.camoal.jwe.JweSerialization.CIPHER_TEXT
import com.camoal.jwe.JweSerialization.ENCRYPTED_KEY
import com.camoal.jwe.JweSerialization.HEADER
import com.camoal.jwe.JweSerialization.IV
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import javax.crypto.Cipher


internal class JweDecoder(
    private val privateKey: PrivateKey,
    private val jwe: String
): JweHelper() {

    fun decode(): String {

        val headerParameters = JweHeader(jwe).decode()

        val algorithm = when(headerParameters[HeaderParameter.ALG]) {
            Algorithm.RSA_OAEP.value -> Algorithm.RSA_OAEP
            Algorithm.RSA_OAEP_256.value -> Algorithm.RSA_OAEP_256
            else -> throw NoSuchAlgorithmException()
        }

        if(headerParameters[HeaderParameter.ENC] != EncryptionAlgorithm.A256GCM.value) {
            throw NoSuchAlgorithmException()
        }

        val compactSerialization = getCompactSerialization(jwe)
        val header = compactSerialization[HEADER]

        val encryptedKey = compactSerialization[ENCRYPTED_KEY].fromBase64()
        val iv = compactSerialization[IV].fromBase64()
        val cipherText = compactSerialization[CIPHER_TEXT].fromBase64()
        val authTag = compactSerialization[AUTHENTICATION_TAG].fromBase64()

        val add = header.toByteArray()
        val asymetricCipher = getAsymetricCipher(privateKey, Cipher.DECRYPT_MODE, algorithm)
        val cek = computeCipher(asymetricCipher, encryptedKey)

        val cipherInput = cipherText + authTag
        val symmetricCipher = getSymmetricCipher(cek, Cipher.DECRYPT_MODE, iv)
        val decipherText = computeCipher(symmetricCipher, cipherInput, add)

        return String(decipherText)
    }
}