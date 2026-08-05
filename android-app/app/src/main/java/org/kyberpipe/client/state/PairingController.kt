package org.kyberpipe.client.state

import android.content.Context
import org.json.JSONObject
import org.kyberpipe.client.utils.SettingsManager

/**
 * Plain (non-Compose) pairing ORCHESTRATION (audit #19 — structural
 * decomposition). The cryptographic core lives in [org.kyberpipe.client.PairingManager]
 * (single canonical KEM/ratchet/epoch-bump sequence); the UI state lives in
 * [PairingState]; the DECISIONS that connect them — presenting the mTLS
 * identity, sending the KEM ciphertext, parsing the host's two-phase response,
 * deriving the session-key handle, pinning the cert, flipping the commit
 * flags — live HERE as pure functions of their inputs. The controller uses NO
 * Compose types, so the pairing state machine can be unit-tested on the JVM
 * without a Compose runtime (the exact untestability the audit flags).
 *
 * All side effects flow through the injected [SettingsManager] / [Context] /
 * `addLog` callback; return values carry the decisions the UI renders.
 */
object PairingController {

    /**
     * Send the KEM ciphertext to the host over QUIC (bootstrap connect with the
     * per-install mTLS identity, audit finding #1) and parse the host's response.
     *
     * Returns the host's `status` string on a successful round-trip
     * ("pairing_pending_sas" when the host accepted and awaits the human SAS
     * verification), or null when the transport/handshake failed.
     */
    fun sendCiphertextAndGetStatus(
        context: Context,
        settings: SettingsManager,
        hostIp: String,
        deviceName: String,
        kemCiphertext: String,
        clientMlkemPkHex: String,
        clientX25519PkHex: String,
        sasCode: String,
        qrServerCertHash: String,
        addLog: (String) -> Unit,
    ): String? {
        // AUDIT FINDING #1 (CRITICAL): the bootstrap connection MUST present
        // the per-install client identity certificate.
        val certHash = org.kyberpipe.client.PairingManager.ensureClientIdentityCert(context)
        val certDer = android.util.Base64.decode(settings.clientIdentityCert, android.util.Base64.NO_WRAP)
        val keyDer = android.util.Base64.decode(settings.clientIdentityKey, android.util.Base64.NO_WRAP)
        try {
            uniffi.core_crypto.quicConnectWithClientCert(
                hostIp, 9876.toUShort(), qrServerCertHash, certDer, keyDer
            )
            addLog("[Pairing] QUIC bridge connected to $hostIp:9876 (mTLS identity presented)")
        } catch (connectErr: Exception) {
            addLog("[Pairing] QUIC connect: ${connectErr.message}")
        } finally {
            // AUDIT #14: wipe the transient identity key bytes the moment the
            // connect (success or error) completes.
            certDer.fill(0)
            keyDer.fill(0)
        }
        val nonceHex = settings.pendingPairingNonce
        val jsonBody = JSONObject()
            .put("name", deviceName)
            .put("ciphertext_hex", kemCiphertext)
            .put("client_pk_hex", clientMlkemPkHex)
            .put("client_x25519_pk_hex", clientX25519PkHex)
            .put("cert_hash_hex", certHash)
            // AUDIT FINDING #10: echo the PHONE's independently computed SAS in
            // the pairing request. The desktop verifies this echo matches the
            // SAS it computed from the same KEM shared secret BEFORE it accepts
            // any human-typed SAS — so a compromised desktop renderer cannot
            // auto-complete the OOB verification by replaying
            // get_pairing_status's SAS.
            .put("sas_hex", sasCode)
        if (nonceHex.isNotEmpty()) {
            jsonBody.put("pairing_nonce_hex", nonceHex)
        }
        return try {
            val response = uniffi.core_crypto.quicSendAndRecv(0x01.toUByte(), jsonBody.toString())
            val respJson = try { JSONObject(response) } catch (_: Exception) { null }
            val status = respJson?.optString("status", "")
            if (status != "pairing_pending_sas") {
                addLog("[Pairing] Host rejected handshake: $response")
            }
            status
        } catch (e: Exception) {
            addLog("[Pairing] QUIC send failed: ${e.message}")
            null
        }
    }
}
