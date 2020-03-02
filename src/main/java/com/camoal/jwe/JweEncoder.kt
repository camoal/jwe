package com.camoal.jwe

import org.json.JSONObject
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.crypto.Cipher


internal class JweEncoder(
    private val certificate: X509Certificate?,
    private val publicKey: PublicKey,
    private val payload: String,
    private val headerParameter: Map<String, Any>,
    private val algorithm: Algorithm
): JweHelper {

    private fun getHeader(): ByteArray {

        val json = JSONObject()
        json.put("alg", algorithm.value)
        json.put("enc", EncryptionAlgorithm.A256GCM.value)
        certificate?.let { certificate ->
            json.put("x5t#S256", certificate.encoded.toSha256().toBase64())
        }
        headerParameter.forEach {
            json.put(it.key, it.value)
        }
        return json.toString().toByteArray()
    }

    private fun generateRandomBytes(size: Int): ByteArray {

        val randomSecureRandom = SecureRandom()
        val randomBytes = ByteArray(size)
        randomSecureRandom.nextBytes(randomBytes)
        return randomBytes
    }

    fun encode(): String {

        val header = getHeader().toBase64()
        val add = header.toByteArray()
        val cek = generateRandomBytes(32)
        val iv = generateRandomBytes(12)
        val symmetricCipher = getSymmetricCipher(cek, Cipher.ENCRYPT_MODE, iv)
        val cipherOutput = computeCipher(symmetricCipher, payload.toByteArray(), add)
        val cipherText = cipherOutput.copyOf(cipherOutput.size - 16).toBase64()
        val authTag = cipherOutput.copyOfRange(cipherOutput.size - 16, cipherOutput.size).toBase64()
        val asymetricCipher = getAsymetricCipher(publicKey, Cipher.ENCRYPT_MODE, algorithm)
        val encryptedKey = computeCipher(asymetricCipher, cek).toBase64()

        return "$header.$encryptedKey.${iv.toBase64()}.$cipherText.$authTag"
    }
}