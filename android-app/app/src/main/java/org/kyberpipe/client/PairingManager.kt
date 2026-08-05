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
    val deviceName: String,
    /// OUR client public halves (hex) needed by the UI to build the pairing
    /// ciphertext payload + SAS. Public, so they cross the boundary freely
    /// (audit #2 follow-up — added so the UI no longer re-derives them, keeping
    /// the handshake in ONE place).
    val clientMlkemPkHex: String,
    val clientX25519PkHex: String,
)

/// AUDIT #12: byte→hex uses the SHARED UniFFI codec (`core_crypto.hexEncode`)
/// — the SAME codec the desktop uses — so the two platforms cannot drift on
/// wire-field serialization. This hand-rolled decoder is retained ONLY for
/// decoding QR/local JSON inputs that predate the shared codec; the encoder
/// path never hand-rolls hex anymore.
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
                try {
                    uniffi.core_crypto.quicConnectWithClientCert(
                        hostIp, port, certPin, certDer, keyDer
                    )
                } finally {
                    // AUDIT #14: the transient PKCS#8 private-key bytes were
                    // decoded into JVM heap for the connect — wipe them the
                    // moment the call returns (success or error) so a heap dump
                    // taken after the connect cannot recover the raw key. The
                    // at-rest copy stays encrypted in EncryptedSharedPreferences.
                    certDer.fill(0)
                    keyDer.fill(0)
                }
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

        val hostIp = json.optString("local_ip", "")
        val deviceName = json.optString("name", "Linux Desktop workstation")
        val pairingNonce = json.optString("pairing_nonce_hex", "")
        // QR-bound server cert hash (audit finding #5/#15): when the QR carries
        // it, this is the pin we trust for the bootstrap QUIC connect instead of
        // capturing the cert from the first connection (TOFU).
        val qrServerCertHash = json.optString("server_cert_hash", "")

        // Wi-Fi Direct (P2P) was removed from the product (audit finding #1) —
        // there is no P2P radio join path anymore; the QR's `method` field, if
        // present, is ignored.

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
        //
        // AUDIT #10 (MEDIUM, "paired but nothing syncs"): a ratchet-init
        // failure is a HARD pairing failure. The legacy catch swallowed the
        // error and the function proceeded to return success=true — but
        // `ratchetRemoveSession` had already run, so NO ratchet session
        // existed: the phone showed paired and green, yet every poll threw
        // "No ratchet session" and nothing ever synced. Fail loudly, destroy
        // the freshly-created KEM handle (no orphaned secret survives), and
        // return null so the UI surfaces the error.
        val peerIdentity = hostPkHex // Use host PK as peer identity
        uniffi.core_crypto.ratchetRemoveSession(peerIdentity)
        try {
            // The Android side is never the ratchet initiator.
            uniffi.core_crypto.ratchetInitSessionFromKemHandle(
                peerIdentity,
                false,
                keyPairHandle,
                kemResponse.handle,
                hexDecode(wireguardPkHex), // peer x25519 pk — enables immediate DH ratchet
                hexDecode(hostPkHex)       // peer mlkem pk — enables immediate KEM ratchet
            )
        } catch (e: Exception) {
            Log.e(TAG, "Ratchet init failed — pairing ABORTED: ${e.message}")
            // Destroy the fresh KEM shared-secret handle so no orphaned secret
            // lingers in Rust zeroizing memory; the caller-owned keypair handle
            // stays (it is persisted per-install and reused for re-pairs).
            try {
                uniffi.core_crypto.destroyKemHandle(kemResponse.handle)
            } catch (_: Exception) {}
            return null
        }
        // AUDIT #10: assert the session actually exists before returning
        // success — a silent init no-op would otherwise present as
        // "paired but nothing syncs".
        val sessionExists = runCatching {
            uniffi.core_crypto.ratchetPeerIds().contains(peerIdentity)
        }.getOrDefault(false)
        if (!sessionExists) {
            Log.e(TAG, "Ratchet session missing after init — pairing ABORTED")
            try {
                uniffi.core_crypto.destroyKemHandle(kemResponse.handle)
            } catch (_: Exception) {}
            return null
        }
        // AUDIT FINDING #2 (HIGH): after a re-pair the fresh session starts at
        // epoch 0 but the OLD pairing's snapshot on disk is also epoch 0 (legacy
        // format) — bump the epoch so the import guard can recognize any stale
        // pre-re-pair snapshot as cross-epoch and refuse it. Without this, a
        // MainActivity recreation after a re-pair would import the old snapshot
        // (old master secret/keypair) over the fresh session — silent state
        // rollback that presents as "paired but nothing syncs".
        uniffi.core_crypto.ratchetBumpPairingEpoch(peerIdentity)

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
                // to PairingController.sendCiphertextAndGetStatus's bootstrap
                // QUIC connect so the server cert is pinned from the QR, not
                // blindly accepted. Empty when the QR carried no hash (legacy
                // accept-any bootstrap).
                settingsManager.pendingServerCertHash = qrServerCertHash
                // The paired desktop's ML-DSA beacon signing public key (audit
                // finding #5): persisted at pairing so the mDNS listener can
                // REJECT beacons whose embedded signing key is not the paired
                // desktop's — an attacker cannot forge a "desktop" beacon.
                val beaconSigningPk = json.optString("beacon_signing_pk", "")
                if (beaconSigningPk.isNotEmpty()) {
                    settingsManager.pairedBeaconSigningKey = beaconSigningPk
                }
            } catch (_: Exception) {}
        }

        return PairingResult(
            success = true,
            hostPkHex = hostPkHex,
            // AUDIT #12: shared codec — the desktop decodes this with the same
            // `hex` implementation this UniFFI call wraps, so the pairing
            // ciphertext cannot drift between platforms.
            kemCiphertext = uniffi.core_crypto.hexEncode(kemResponse.ciphertext),
            sessionKeyHandle = sessionKeyHandle,
            kemHandleId = kemResponse.handle,
            sasCode = computedSas,
            hostIp = hostIp,
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

}