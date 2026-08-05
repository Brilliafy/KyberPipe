package org.kyberpipe.client.service

import org.kyberpipe.client.utils.SettingsManager

/**
 * The MINIMAL settings surface `PollTransport` reads/writes. Extracted so the
 * transport is unit-testable on the JVM with a fake — the full
 * [SettingsManager] needs EncryptedSharedPreferences (Android Keystore), which
 * cannot run in a plain JVM test (verification-gap remediation).
 */
interface PollSettings {
    var pendingPairingConfirmation: Boolean
    var isPaired: Boolean
    var pairedDeviceName: String
}

/** [SettingsManager] satisfies the transport's settings contract. */
@Suppress("unused")
val SettingsManager.asPollSettings: PollSettings
    get() = this

/**
 * The ratchet FFI surface `PollTransport` uses. Real impl delegates to
 * `uniffi.core_crypto`; tests inject a fake so the poll wire logic — including
 * the critical AUDIT #1 flow-forwarding — runs hermetically on the JVM.
 */
interface PollFfi {
    /** Phone→desktop authenticated Synchronize packet (audit #12). Throws on failure. */
    fun synchronizePacketBinary(peer: String): ByteArray
    /** Non-consuming peek of the phone's outbound RekeyAck TLV (audit #6). */
    fun generateRekeyAckBinaryPeek(peer: String): ByteArray?
    /** Process the desktop's RekeyAck (commits our outgoing proposal). */
    fun processRekeyAckBinary(peer: String, tlv: ByteArray)
    /** Process the desktop's authenticated Synchronize carrier (audit #4). */
    fun processSynchronize(peer: String, tlv: ByteArray)
    /** Decrypt a binary-TLV ratchet message (rekey-aware in Rust). Throws on failure. */
    fun decryptMessageBinary(peer: String, tlv: ByteArray): ByteArray
}

/** Production impl: thin delegation to the UniFFI bindings. */
class RealPollFfi : PollFfi {
    override fun synchronizePacketBinary(peer: String): ByteArray =
        uniffi.core_crypto.ratchetSynchronizePacketBinary(peer)

    override fun generateRekeyAckBinaryPeek(peer: String): ByteArray? =
        uniffi.core_crypto.ratchetGenerateRekeyAckBinaryPeek(peer)

    override fun processRekeyAckBinary(peer: String, tlv: ByteArray) {
        uniffi.core_crypto.ratchetProcessRekeyAckBinary(peer, tlv)
    }

    override fun processSynchronize(peer: String, tlv: ByteArray) {
        uniffi.core_crypto.ratchetProcessSynchronize(peer, tlv)
    }

    override fun decryptMessageBinary(peer: String, tlv: ByteArray): ByteArray =
        uniffi.core_crypto.ratchetDecryptMessageBinary(peer, tlv)
}
