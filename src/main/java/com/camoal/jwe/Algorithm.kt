package com.camoal.jwe

enum class Algorithm(internal val value: String) {
    RSA_OAEP("RSA-OAEP"),
    RSA_OAEP_256("RSA-OAEP-256")
}