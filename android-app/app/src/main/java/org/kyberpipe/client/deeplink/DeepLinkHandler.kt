package org.kyberpipe.client.deeplink

import android.content.Intent
import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.util.zip.InflaterInputStream

/**
 * Pairing deep-link handler (audit finding #22).
 *
 * Hardening applied:
 *  - The pairing payload MUST arrive as the `data` query parameter. The old
 *    `kyberpipe://pair` fallback passed the ENTIRE URI (scheme + query) as the
 *    pairing payload — raw data injection into the pairing flow. That path is
 *    forbidden.
 *  - The decoded payload MUST carry a well-formed QR pairing token
 *    (`pairing_nonce_hex`, 32 hex — the app/server-issued freshness token) and
 *    the QR-bound server certificate pin (`server_cert_hash`, 64 hex). A link
 *    missing either is treated as suspicious (pairing phishing / stale replay).
 *  - Every accepted link is flagged `fromLink` so the UI can surface an
 *    explicit "pairing initiated from a link — verify the host identity"
 *    prompt before the payload is consumed.
 */
object DeepLinkHandler {

    data class Result(
        val valid: Boolean,
        val data: String? = null,
        val fromLink: Boolean = false,
        val warning: String? = null,
    )

    private val NONCE_RE = Regex("[0-9a-fA-F]{32}")
    private val CERT_HASH_RE = Regex("[0-9a-fA-F]{64}")

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

        // Audit finding #22: a pairing payload MUST be delivered as the `data`
        // query parameter. The old kyberpipe://pair fallback that passed
        // uri.toString() as the payload (raw injection) is removed.
        val dataParam = uri.getQueryParameter("data")
        if (dataParam.isNullOrEmpty()) {
            Log.w("KyberpipeIntent", "Rejected deep link without a data payload: $uri")
            return Result(false)
        }

        val warning = validatePayload(dataParam)
        return Result(valid = true, data = dataParam, fromLink = true, warning = warning)
    }

    /**
     * Decode the base64(zlib) pairing payload and validate that it carries the
     * app/server-issued pairing token and the QR-bound cert pin. Returns a
     * warning describing what is missing, or null when the link is well-formed.
     */
    private fun validatePayload(data: String): String? {
        return try {
            val decoded = Base64.decode(data, Base64.DEFAULT)
            val jsonStr = InflaterInputStream(ByteArrayInputStream(decoded)).bufferedReader().readText()
            val json = JSONObject(jsonStr)
            val nonce = json.optString("pairing_nonce_hex", "")
            val certHash = json.optString("server_cert_hash", "")
            when {
                nonce.isEmpty() || !NONCE_RE.matches(nonce) ->
                    "The pairing link carries no valid QR pairing token — it may be a forged or stale link."
                certHash.isEmpty() || !CERT_HASH_RE.matches(certHash) ->
                    "The pairing link carries no server certificate pin — the connection cannot be verified."
                else -> null
            }
        } catch (e: Exception) {
            "The pairing link payload could not be decoded."
        }
    }
}
