package org.kyberpipe.client

import android.content.Context
import android.util.Log
import android.widget.Toast
import org.json.JSONObject
import uniffi.core_crypto.generateSasCode
import uniffi.core_crypto.encapsulatePqSecret
import uniffi.core_crypto.deriveSessionKey
import uniffi.core_crypto.generatePqKeypair
import org.kyberpipe.client.utils.SettingsManager

data class PairingResult(
    val success: Boolean,
    val hostPkHex: String,
    val kemCiphertext: String,
    val sessionKey: List<UByte>,
    val sasCode: String,
    val hostIp: String,
    val p2pIp: String,
    val deviceName: String
)

private fun hexDecode(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "Hex string must have even length" }
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
object PairingManager {
    private const val TAG = "KyberpipePairing"

    /// Ensure a per-install client identity certificate exists and persist it.
    /// Returns the cert hash (hex). Generated once per install; reused for
    /// every connection so the desktop's pinned identity stays stable
    /// (audit finding #8).
    fun ensureClientIdentityCert(context: android.content.Context): String {
        val settings = SettingsManager(context)
        if (settings.clientIdentityCert.isNotEmpty() && settings.clientIdentityKey.isNotEmpty()) {
            return settings.clientIdentityCertHash
        }
        return try {
            val identity = uniffi.core_crypto.generateClientIdentityCert()
            settings.clientIdentityCert = android.util.Base64.encodeToString(
                identity.certDer, android.util.Base64.NO_WRAP
            )
            settings.clientIdentityKey = android.util.Base64.encodeToString(
                identity.keyDer, android.util.Base64.NO_WRAP
            )
            settings.clientIdentityCertHash = identity.sha256Hex
            identity.sha256Hex
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate client identity cert: ${e.message}")
            ""
        }
    }

    /// Connect to the desktop with the per-install identity certificate.
    /// Post-pairing connects pass the pin AND the identity cert so the server
    /// authorizes by cert hash (audit findings #6/#8).
    fun connectWithIdentity(
        hostIp: String,
        port: UShort,
        certPin: String,
        context: android.content.Context,
    ): Boolean {
        val settings = SettingsManager(context)
        val hasIdentity =
            settings.clientIdentityCert.isNotEmpty() && settings.clientIdentityKey.isNotEmpty()
        return try {
            if (hasIdentity) {
                val certDer = android.util.Base64.decode(
                    settings.clientIdentityCert, android.util.Base64.NO_WRAP
                )
                val keyDer = android.util.Base64.decode(
                    settings.clientIdentityKey, android.util.Base64.NO_WRAP
                )
                uniffi.core_crypto.quicConnectWithClientCert(
                    hostIp, port, certPin, certDer, keyDer
                )
            } else {
                uniffi.core_crypto.quicConnect(hostIp, port, certPin)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Identity QUIC connect failed: ${e.message}")
            false
        }
    }

    /// Perform the KEM handshake against the host's public keys.
    /// Returns a PairingResult if successful, null on failure.
    fun performKemHandshake(json: JSONObject, keyPair: uniffi.core_crypto.PqKeyPair?, context: android.content.Context? = null): PairingResult? {
        val hostPkHex = json.optString("pqc_pub", json.optString("host_identity_pk_hex", ""))
        val wireguardPkHex = json.optString("x25519_pub", json.optString("wireguard_pk_hex", ""))
        if (hostPkHex.isEmpty() || wireguardPkHex.isEmpty()) return null

        val hostIp = json.optString("local_ip", json.optString("p2p_ip", ""))
        val p2pIp = json.optString("p2p_ip", "")
        val deviceName = json.optString("name", "Linux Desktop workstation")
        val pairingNonce = json.optString("pairing_nonce_hex", "")

        // Handle P2P Wi-Fi connection
        val method = json.optString("method", "")
        if (method == "p2p") {
            connectP2p(json, hostPkHex)
        }

        val kemResponse = encapsulatePqSecret(hexDecode(wireguardPkHex), hexDecode(hostPkHex))
        val myPkHex = keyPair?.mlkemPk?.joinToString("") { "%02x".format(it) } ?: ""
        val computedSas = generateSasCode(hexDecode(hostPkHex), hexDecode(myPkHex), kemResponse.sharedSecret)
        // Canonical domain-separation salt — SAME bytes as the desktop, taken
        // from the UniFFI export (audit finding #2). Never re-encode hex-as-ASCII.
        val sessionKeyHex = deriveSessionKey(
            kemResponse.sharedSecret,
            uniffi.core_crypto.sessionDerivationSalt()
        )
        val sessionKey = sessionKeyHex

        // Initialize ratchet session for peer with hybrid public keys.
        // Remove any stale session first (re-pair scenario), then init fresh.
        try {
            val peerIdentity = hostPkHex // Use host PK as peer identity
            uniffi.core_crypto.ratchetRemoveSession(peerIdentity)
            uniffi.core_crypto.ratchetInitSession(
                peerIdentity,
                kemResponse.sharedSecret,
                false, // Android is not the initiator
                hexDecode(wireguardPkHex), // peer x25519 pk — enables immediate DH ratchet
                hexDecode(hostPkHex)       // peer mlkem pk — enables immediate KEM ratchet
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to init ratchet session: ${e.message}")
        }

        // Store peer identity for clipboard/notification handlers
        if (context != null) {
            try {
                val settingsManager = SettingsManager(context)
                settingsManager.peerRatchetIdentity = hostPkHex
                // The QR nonce binding (audit #20): remember the nonce this QR
                // carried so it can be echoed in the pairing payload.
                if (pairingNonce.isNotEmpty()) {
                    settingsManager.pendingPairingNonce = pairingNonce
                }
            } catch (_: Exception) {}
        }

        return PairingResult(
            success = true,
            hostPkHex = hostPkHex,
            kemCiphertext = kemResponse.ciphertext.joinToString("") { "%02x".format(it) },
            sessionKey = sessionKey.toList().map { it.toUByte() },
            sasCode = computedSas,
            hostIp = hostIp,
            p2pIp = p2pIp,
            deviceName = deviceName
        )
    }

    /// Send the pairing ciphertext to the host over QUIC.
    /// Establishes the QUIC bridge first (the transport plane that all streams
    /// use) and returns the response status string, or null on failure.
    fun sendCiphertext(hostIp: String, deviceName: String, kemCiphertext: String, clientPkHex: String, x25519PkHex: String, context: android.content.Context? = null): String? {
        return try {
            // Establish the QUIC bridge to the desktop before sending any stream.
            // Bootstrap pairing uses the allow-private connect (the SSRF guard
            // previously blocked private-IP connects with an empty pin — audit #6).
            try {
                uniffi.core_crypto.quicConnectPairingBootstrap(hostIp, 9876.toUShort())
            } catch (connectErr: Exception) {
                Log.e(TAG, "QUIC connect failed: ${connectErr.message}")
            }
            var certHash = ""
            var nonceHex = ""
            if (context != null) {
                val settings = SettingsManager(context)
                certHash = settings.clientIdentityCertHash
                nonceHex = settings.pendingPairingNonce
            }
            val json = JSONObject().apply {
                put("type", "pairing")
                put("ciphertext_hex", kemCiphertext)
                put("client_pk_hex", clientPkHex)
                put("client_x25519_pk_hex", x25519PkHex)
                put("name", deviceName)
                put("cert_hash_hex", certHash)
                if (nonceHex.isNotEmpty()) {
                    put("pairing_nonce_hex", nonceHex)
                }
            }
            uniffi.core_crypto.quicSendAndRecv(0x01.toUByte(), json.toString())
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send ciphertext: ${e.message}")
            null
        }
    }

    private fun connectP2p(json: JSONObject, hostPkHex: String) {
        val ssid = json.optString("p2p_ssid", "")
        val password = json.optString("p2p_password", "")
        val goIp = json.optString("p2p_ip", "")
        if (ssid.isNotEmpty() && password.isNotEmpty()) {
            try {
                // Connect to P2P Wi-Fi via native bridge
                // uniffi.core_crypto.connectP2pWifi(ssid, password, goIp)
                // Note: connectP2pWifi doesn't exist yet, placeholder
            } catch (e: Exception) {
                Log.e(TAG, "P2P connection failed: ${e.message}")
            }
        }
    }
}
