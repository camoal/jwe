package com.camoal.jwe

import org.json.JSONObject


class JweHeader(
    private val jwe: String
): JweHelper {

    fun decode(): MutableMap<String, Any> {

        val header = String(jwe.parse()[0].trim().fromBase64())

        val map: MutableMap<String, Any> = HashMap()

        val jsonObject = JSONObject(header)
        val keys: Iterator<String> = jsonObject.keys()

        keys.forEach { key ->
            map[key] = jsonObject.get(key)
        }

        return map
    }
}