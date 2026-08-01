package org.kyberpipe.client.deeplink

import android.content.Intent
import android.util.Log

object DeepLinkHandler {
    data class Result(
        val valid: Boolean,
        val data: String? = null
    )

    fun parse(intent: Intent?): Result {
        val uri = intent?.data ?: return Result(false)
        val scheme = uri.scheme ?: ""
        val host = uri.host ?: ""

        // Validate URI origin — prevent malicious apps from injecting
        // spoofed pairing data via arbitrary intents.
        val validOrigin = when (scheme) {
            "kyberpipe" -> host == "pair"
            "https" -> host == "brilliafy.github.io" && uri.path?.startsWith("/kyberpipe/pair") == true
            else -> false
        }
        if (!validOrigin) {
            Log.w("KyberpipeIntent", "Rejected deep link from untrusted origin: $scheme://$host${uri.path}")
            return Result(false)
        }

        val dataParam = uri.getQueryParameter("data")
        val data = if (!dataParam.isNullOrEmpty()) dataParam else uri.toString()
        return Result(true, data)
    }
}
