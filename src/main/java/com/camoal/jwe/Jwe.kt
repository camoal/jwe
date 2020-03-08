package com.camoal.jwe

import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate


abstract class Jwe {

    class Builder {

        private var algorithm = Algorithm.RSA_OAEP
        private var certificate: X509Certificate? = null
        private lateinit var publicKey: PublicKey
        private lateinit var payload: String
        private var headerParameter = mutableMapOf<String, Any>()

        fun algorithm(algorithm: Algorithm) = apply {
            this.algorithm = algorithm
        }

        fun certificate(certificate: X509Certificate) = apply {
            this.certificate = certificate
            this.publicKey = certificate.publicKey
        }

        fun publicKey(publicKey: PublicKey) = apply {
            this.publicKey = publicKey
        }

        fun headerParameter(key: String, value: Any) = apply {
            headerParameter[key] = value
        }

        fun payload(payload: String) = apply {
            this.payload = payload
        }

        fun build(): String {
            return JweEncoder(
                certificate,
                publicKey,
                payload,
                headerParameter,
                algorithm
            ).encode()
        }
    }

    class Parser {

        private lateinit var privateKey: PrivateKey
        private lateinit var jwe: String

        fun jwe(jwe: String) = apply {
            this.jwe = jwe
        }

        fun privateKey(privateKey: PrivateKey) = apply {
            this.privateKey = privateKey
        }

        fun headerParameters(): MutableMap<String, Any> {
            return JweHeader(
                jwe
            ).decode()
        }

        fun parse(): String {
            return JweDecoder(
                privateKey,
                jwe
            ).decode()
        }
    }
}