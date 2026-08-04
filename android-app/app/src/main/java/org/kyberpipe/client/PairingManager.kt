package org.kyberpipe.client

import android.content.Context
import android.util.Log
import org.json.JSONObject
import org.kyberpipe.client.utils.SettingsManager

data class PairingResult(
    val success: Boolean,
    val hostPkHex: String,
    val kemCiphertext: String,
    /// Opaque Rust-side session-key handle (ULong). Raw key bytes never leave Rust.
    val sessionKeyHandle: ULong,
    /// Opaque Rust-side KEM shared-secret handle (ULong), destroyed on unpair.
    val kemHandleId: ULong,
    val sasCode: String,
    val hostIp: String,
    val p2pIp: String,
    val deviceName: String,
    /// OUR client public halves (hex) needed by the UI to build the pairing
    /// ciphertext payload + SAS. Public, so they cross the boundary freely
    /// (audit #2 follow-up — added so the UI no longer re-derives them, keeping
    /// the handshake in ONE place).
    val clientMlkemPkHex: String,
    val clientX25519PkHex: String,
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
    /// authorizes by cert hash (audit findings #6/#8). `certPin` is the
    /// post-SAS serverCertPin persisted at SAS confirmation (audit #15).
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
    ///
    /// Everything secret stays in Rust opaque handles (audit finding F7): the
    /// hybrid keypair is referenced by [keyPairHandle], the KEM shared secret by
    /// the returned [PairingResult.kemHandleId], and the derived session key by
    /// [PairingResult.sessionKeyHandle]. Raw x25519Sk/mlkemSk/sharedSecret bytes
    /// never cross the FFI boundary.
    ///
    /// Returns a PairingResult if successful, null on failure. A missing keypair
    /// handle is a hard failure — there is NO legacy keypair-less ratchet init
    /// anymore (the regenerated FFI removed ratchetInitSession), so pairing fails
    /// loudly instead of silently using a fresh ephemeral keypair.
    fun performKemHandshake(
        json: JSONObject,
        keyPairHandle: ULong?,
        context: android.content.Context? = null,
    ): PairingResult? {
        if (keyPairHandle == null) {
            Log.e(TAG, "Pairing aborted: no hybrid keypair handle — a generated keypair is required for the KEM handshake")
            return null
        }
        val hostPkHex = json.optString("pqc_pub", json.optString("host_identity_pk_hex", ""))
        val wireguardPkHex = json.optString("x25519_pub", json.optString("wireguard_pk_hex", ""))
        if (hostPkHex.isEmpty() || wireguardPkHex.isEmpty()) return null

        val hostIp = json.optString("local_ip", json.optString("p2p_ip", ""))
        val p2pIp = json.optString("p2p_ip", "")
        val deviceName = json.optString("name", "Linux Desktop workstation")
        val pairingNonce = json.optString("pairing_nonce_hex", "")
        // QR-bound server cert hash (audit finding #5/#15): when the QR carries
        // it, this is the pin we trust for the bootstrap QUIC connect instead of
        // capturing the cert from the first connection (TOFU).
        val qrServerCertHash = json.optString("server_cert_hash", "")

        // Handle P2P Wi-Fi connection
        val method = json.optString("method", "")
        if (method == "p2p") {
            connectP2p(json, hostPkHex)
        }

        // KEM encapsulate on the keypair handle — the shared secret stays in Rust
        // and is referenced by kemHandleId. Only the (public) ciphertext and the
        // peer's public halves cross the boundary.
        val kemResponse = uniffi.core_crypto.encapsulatePqSecretHandle(
            hexDecode(wireguardPkHex),
            hexDecode(hostPkHex)
        )
        val clientPublic = uniffi.core_crypto.getPqKeypairPublic(keyPairHandle)
        val clientMlkemPkBytes = hexDecode(clientPublic.mlkemPkHex)
        val computedSas = uniffi.core_crypto.generateSasCodeWithKemHandle(
            hexDecode(hostPkHex),
            clientMlkemPkBytes,
            kemResponse.handle
        )

        // Initialize ratchet session for peer with hybrid public keys, using the
        // KEM handle (NO raw secrets — audit finding F7). Remove any stale
        // session first (re-pair scenario), then init fresh.
        try {
            val peerIdentity = hostPkHex // Use host PK as peer identity
            uniffi.core_crypto.ratchetRemoveSession(peerIdentity)
            // The Android side is never the ratchet initiator.
            uniffi.core_crypto.ratchetInitSessionFromKemHandle(
                peerIdentity,
                false,
                keyPairHandle,
                kemResponse.handle,
                hexDecode(wireguardPkHex), // peer x25519 pk — enables immediate DH ratchet
                hexDecode(hostPkHex)       // peer mlkem pk — enables immediate KEM ratchet
            )
            // AUDIT FINDING #2 (HIGH): after a re-pair the fresh session starts at
            // epoch 0 but the OLD pairing's snapshot on disk is also epoch 0 (legacy
            // format) — bump the epoch so the import guard can recognize any stale
            // pre-re-pair snapshot as cross-epoch and refuse it. Without this, a
            // MainActivity recreation after a re-pair would import the old snapshot
            // (old master secret/keypair) over the fresh session — silent state
            // rollback that presents as "paired but nothing syncs".
            uniffi.core_crypto.ratchetBumpPairingEpoch(peerIdentity)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to init ratchet session: ${e.message}")
        }

        // Derive the opaque session-key handle from the KEM handle. The derived
        // key bytes stay in Rust zeroizing memory; only the handle is returned.
        val sessionKeyHandle = uniffi.core_crypto.deriveSessionKeyHandle(kemResponse.handle)

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
                // QR-bound server cert hash (audit finding #5/#15): pass it down
                // to sendCiphertext's bootstrap QUIC connect so the server cert
                // is pinned from the QR, not blindly accepted. Empty when the QR
                // carried no hash (legacy accept-any bootstrap).
                settingsManager.pendingServerCertHash = qrServerCertHash
            } catch (_: Exception) {}
        }

        return PairingResult(
            success = true,
            hostPkHex = hostPkHex,
            kemCiphertext = kemResponse.ciphertext.joinToString("") { "%02x".format(it) },
            sessionKeyHandle = sessionKeyHandle,
            kemHandleId = kemResponse.handle,
            sasCode = computedSas,
            hostIp = hostIp,
            p2pIp = p2pIp,
            deviceName = deviceName,
            clientMlkemPkHex = clientPublic.mlkemPkHex,
            clientX25519PkHex = clientPublic.x25519PkHex
        )
    }

    /// Destroy every Rust-side pairing handle still referenced by this install
    /// (keypair, KEM shared secret, session key) and clear the stored handles.
    /// Called on unpair/self-destruct so the zeroizing memory is released and
    /// a stale handle can never be reused (audit finding F7).
    fun destroyPairingHandles(context: Context) {
        val settings = SettingsManager(context)
        val keypairHandle = settings.keypairHandle
        if (keypairHandle != 0L) {
            try {
                uniffi.core_crypto.destroyPqKeypairHandle(keypairHandle.toULong())
            } catch (e: Exception) {
                Log.e(TAG, "Keypair handle destroy failed: ${e.message}")
            }
            settings.keypairHandle = 0L
        }
        val kemHandleId = settings.kemHandleId
        if (kemHandleId != 0L) {
            try {
                uniffi.core_crypto.destroyKemHandle(kemHandleId.toULong())
            } catch (e: Exception) {
                Log.e(TAG, "KEM handle destroy failed: ${e.message}")
            }
            settings.kemHandleId = 0L
        }
        val sessionKeyHandle = settings.sessionKeyHandle
        if (sessionKeyHandle != 0L) {
            try {
                uniffi.core_crypto.sessionKeyDestroy(sessionKeyHandle.toULong())
            } catch (e: Exception) {
                Log.e(TAG, "Session key handle destroy failed: ${e.message}")
            }
            settings.sessionKeyHandle = 0L
        }
    }

    /// Send the pairing ciphertext to the host over QUIC.
    /// Establishes the QUIC bridge first (the transport plane that all streams
    /// use) and returns the response status string, or null on failure.
    fun sendCiphertext(hostIp: String, deviceName: String, kemCiphertext: String, clientPkHex: String, x25519PkHex: String, context: android.content.Context? = null): String? {
        return try {
            val settings = context?.let { SettingsManager(it) }
            // Audit finding #15: the QR-bound server certificate pin is MANDATORY
            // for the bootstrap connection. Without it the desktop's certificate
            // would be accepted blindly and a LAN MITM could terminate TLS,
            // forward the KEM, and hold every session key while the SAS still
            // matches. Fail loudly instead of proceeding.
            val pin = settings?.pendingServerCertHash ?: ""
            if (pin.isEmpty()) {
                Log.e(TAG, "Pairing aborted: the QR carried no server certificate pin — refusing unverified bootstrap (MITM protection)")
                return null
            }
            // AUDIT FINDING #1 (CRITICAL): the bootstrap connection MUST present
            // the per-install client identity certificate. The desktop pins the
            // TLS-OBSERVED client cert at pairing time; a cert-less bootstrap
            // leaves the pin empty, skips the mTLS rebind, and rejects every
            // post-pairing stream ("paired but nothing syncs"). Generate the
            // identity BEFORE connecting and present it on the SAME connection
            // that carries the KEM — single connect path, no cert-less pairing
            // variant.
            val identity = ensureClientIdentityCert(context ?: return null)
            if (identity.isEmpty()) {
                Log.e(TAG, "Pairing aborted: failed to generate the client identity certificate")
                return null
            }
            val settings2 = SettingsManager(context!!)
            if (settings2.clientIdentityCert.isEmpty() || settings2.clientIdentityKey.isEmpty()) {
                Log.e(TAG, "Pairing aborted: client identity certificate not persisted")
                return null
            }
            val certDer = android.util.Base64.decode(settings2.clientIdentityCert, android.util.Base64.NO_WRAP)
            val keyDer = android.util.Base64.decode(settings2.clientIdentityKey, android.util.Base64.NO_WRAP)
            // Establish the QUIC bridge to the desktop before sending any stream.
            // Presents the client identity cert (audit finding #1) AND pins the
            // QR-bound server cert (audit finding #15).
            try {
                uniffi.core_crypto.quicConnectWithClientCert(
                    hostIp,
                    9876.toUShort(),
                    pin,
                    certDer,
                    keyDer
                )
            } catch (connectErr: Exception) {
                Log.e(TAG, "QUIC connect failed: ${connectErr.message}")
                return null
            }
            var certHash = identity
            var nonceHex = ""
            if (settings != null) {
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
            // P2P Wi-Fi pairing is NOT implemented in this build — the stub that
            // previously pretended to connect (a silent no-op behind a try/catch)
            // is removed so the caller cannot rely on it (audit KYP-2026-02 #25).
            Log.w(TAG, "connectP2p: P2P Wi-Fi pairing is unavailable in this build")
        }
    }
}
