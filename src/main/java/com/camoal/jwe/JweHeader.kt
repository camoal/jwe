package com.camoal.jwe

import com.camoal.jwe.JweSerialization.HEADER
import org.json.JSONObject


internal class JweHeader(
    private val jwe: String
): JweHelper() {

    fun decode(): MutableMap<String, Any> {

        val header = String(getCompactSerialization(jwe)[HEADER].fromBase64())

        val map: MutableMap<String, Any> = HashMap()

        val jsonObject = JSONObject(header)
        val keys: Iterator<String> = jsonObject.keys()

        keys.forEach { key ->
            map[key] = jsonObject.get(key)
        }

        return map
    }
}