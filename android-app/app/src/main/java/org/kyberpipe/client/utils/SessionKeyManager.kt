package org.kyberpipe.client.utils

import android.util.Log
import uniffi.core_crypto.sessionKeyCreate
import uniffi.core_crypto.sessionKeyDestroy
import uniffi.core_crypto.sessionKeyEncrypt
import uniffi.core_crypto.sessionKeyDecrypt

/**
 * Manages an opaque session key handle. Raw key bytes never cross the FFI boundary
 * after initial creation. The handle is a u64 ID; Rust retains the key in zeroizing memory.
 */
object SessionKeyManager {
    private const val TAG = "KyberpipeSessionKey"

    @Volatile
    private var handle: Long? = null

    /**
     * Initialize the session key handle from raw bytes.
     * Must be called once after pairing completes with the derived session key bytes.
     */
    @Synchronized
    fun init(keyBytes: ByteArray) {
        val newHandle = try {
            sessionKeyCreate(keyBytes)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create session key handle: ${e.message}")
            null
        }
        // Destroy old handle after creating new one
        handle?.let {
            try { sessionKeyDestroy(it.toULong()) } catch (_: Exception) {}
        }
        handle = newHandle?.toLong()
    }

    /**
     * Initialize from a hex-encoded session key string.
     */
    @Synchronized
    fun initFromHex(hexKey: String) {
        val bytes = hexDecode(hexKey)
        init(bytes)
    }

    /**
     * Encrypt data using the session key handle.
     * Returns EncryptedPayload with nonce and ciphertext, or null on failure.
     */
    @Synchronized
    fun encrypt(data: String): uniffi.core_crypto.EncryptedPayload? {
        val h = handle ?: return null
        return try {
            sessionKeyEncrypt(h.toULong(), data.toByteArray())
        } catch (e: Exception) {
            Log.e(TAG, "Encrypt failed: ${e.message}")
            null
        }
    }

    /**
     * Decrypt data using the session key handle.
     * Returns decrypted string, or null on failure.
     */
    @Synchronized
    fun decrypt(nonce: ByteArray, ciphertext: ByteArray): String? {
        val h = handle ?: return null
        return try {
            val result = sessionKeyDecrypt(h.toULong(), nonce, ciphertext)
            String(result)
        } catch (e: Exception) {
            Log.e(TAG, "Decrypt failed: ${e.message}")
            null
        }
    }

    /**
     * Check if a valid session key handle exists.
     */
    @Synchronized
    fun isActive(): Boolean = handle != null

    /**
     * Destroy the session key handle, zeroizing the key material in Rust memory.
     */
    @Synchronized
    fun destroy() {
        handle?.let {
            try {
                sessionKeyDestroy(it.toULong())
            } catch (e: Exception) {
                Log.e(TAG, "Failed to destroy session key handle: ${e.message}")
            }
        }
        handle = null
    }

    private fun hexDecode(hex: String): ByteArray {
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
