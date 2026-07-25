package org.kyberpipe.client

import android.content.Context
import android.util.Log
import android.widget.Toast
import org.json.JSONObject
import uniffi.core_crypto.generateSasCode
import uniffi.core_crypto.encapsulatePqSecret
import uniffi.core_crypto.deriveSessionKey
import uniffi.core_crypto.generatePqKeypair

data class PairingResult(
    val success: Boolean,
    val hostPkHex: String,
    val kemCiphertext: String,
    val sessionKey: String,
    val sasCode: String,
    val hostIp: String,
    val p2pIp: String,
    val deviceName: String
)

object PairingManager {
    private const val TAG = "KyberpipePairing"

    /// Perform the KEM handshake against the host's public keys.
    /// Returns a PairingResult if successful, null on failure.
    fun performKemHandshake(json: JSONObject, keyPair: uniffi.core_crypto.PqKeyPair?): PairingResult? {
        val hostPkHex = json.optString("pqc_pub", json.optString("host_identity_pk_hex", ""))
        val wireguardPkHex = json.optString("x25519_pub", json.optString("wireguard_pk_hex", ""))
        if (hostPkHex.isEmpty() || wireguardPkHex.isEmpty()) return null

        val hostIp = json.optString("local_ip", json.optString("p2p_ip", ""))
        val p2pIp = json.optString("p2p_ip", "")
        val deviceName = json.optString("name", "Linux Desktop workstation")

        // Handle P2P Wi-Fi connection
        val method = json.optString("method", "")
        if (method == "p2p") {
            connectP2p(json, hostPkHex)
        }

        val kemResponse = encapsulatePqSecret(wireguardPkHex, hostPkHex)
        val myPkHex = keyPair?.mlkemPkHex ?: ""
        val computedSas = generateSasCode(hostPkHex, myPkHex, kemResponse.sharedSecretHex)
        val sessionKey = deriveSessionKey(kemResponse.sharedSecretHex, hostPkHex)

        return PairingResult(
            success = true,
            hostPkHex = hostPkHex,
            kemCiphertext = kemResponse.ciphertextHex,
            sessionKey = sessionKey,
            sasCode = computedSas,
            hostIp = hostIp,
            p2pIp = p2pIp,
            deviceName = deviceName
        )
    }

    /// Send the pairing ciphertext to the host over QUIC.
    /// Returns the response status string, or null on failure.
    fun sendCiphertext(hostIp: String, deviceName: String, kemCiphertext: String, clientPkHex: String): String? {
        try {
            val jsonBody = JSONObject()
                .put("name", deviceName)
                .put("ciphertext_hex", kemCiphertext)
                .put("client_pk_hex", clientPkHex)
                .toString()
            val response = uniffi.core_crypto.quicSendAndRecv(0x01.toUByte(), jsonBody)
            val respJson = try { JSONObject(response) } catch (_: Exception) { null }
            return respJson?.optString("status", "")
        } catch (e: Exception) {
            Log.e(TAG, "QUIC send failed: ${e.message}")
            return null
        }
    }

    private fun connectP2p(json: JSONObject, hostPkHex: String) {
        val ssid = json.optString("ssid", "")
        val pass = json.optString("pass", "")
        if (ssid.isEmpty()) return
        // Wi-Fi P2P connection logic extracted from MainActivity
        Log.d(TAG, "Would connect to P2P SSID: $ssid")
    }
}
