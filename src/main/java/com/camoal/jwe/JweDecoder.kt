package com.camoal.jwe

import org.json.JSONObject
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import javax.crypto.Cipher


internal class JweDecoder(
    private val privateKey: PrivateKey,
    private val jwe: String
): JweHelper {

    fun decode(): JweDecoded {

        val list = jwe.parse()

        val header = list[0]
        val plainHeader = String(header.fromBase64())
        val jsonObject = JSONObject(plainHeader)

        val algorithm = when(jsonObject.getString("alg")) {
            Algorithm.RSA_OAEP.value -> Algorithm.RSA_OAEP
            Algorithm.RSA_OAEP_256.value -> Algorithm.RSA_OAEP_256
            else -> throw NoSuchAlgorithmException()
        }

        if(jsonObject.getString("enc") != EncryptionAlgorithm.A256GCM.value) {
            throw NoSuchAlgorithmException()
        }

        val encryptedKey = list[1].fromBase64()
        val iv = list[2].fromBase64()
        val cipherText = list[3].fromBase64()
        val authTag = list[4].fromBase64()

        val add = header.toByteArray()
        val asymetricCipher = getAsymetricCipher(privateKey, Cipher.DECRYPT_MODE, algorithm)
        val cek = computeCipher(asymetricCipher, encryptedKey)

        val cipherInput = cipherText + authTag
        val symmetricCipher = getSymmetricCipher(cek, Cipher.DECRYPT_MODE, iv)
        val decipherText = computeCipher(symmetricCipher, cipherInput, add)

        return JweDecoded(String(header.fromBase64()), String(decipherText))
    }
}