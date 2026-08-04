package org.kyberpipe.client.utils

import org.json.JSONObject
import uniffi.core_crypto.RatchetWatermark

/**
 * Monotonic ratchet rollback watermark, one entry per peer (audit #2
 * follow-up). Mirrors the core-crypto `RatchetWatermark` 4-tuple
 * `(pairing_epoch, ratchet_generation, send_message_count,
 * recv_message_count)` and the desktop store's high-water-mark discipline:
 *
 *  - the watermark is stored in EncryptedSharedPreferences (Android
 *    Keystore-backed AES-256-GCM), so a same-user process that restores an OLD
 *    wrapped snapshot blob cannot regress it;
 *  - the persist path records `max(stored, live)` AFTER a successful snapshot
 *    export, so the recorded mark only ever moves forward;
 *  - the cold-start restore path refuses any snapshot whose watermark is
 *    STRICTLY below the recorded mark (equal = the current snapshot, accepted),
 *    closing the snapshot-to-snapshot regression the live-session registry
 *    guard cannot see (on a cold start the registry is empty).
 *
 * Comparing two watermarks is lexicographic over the 4-tuple, matching the
 * Rust registry guard.
 */
object RatchetWatermarkStore {

    /** Parse the persisted JSON map `{ "<peer>": [epoch, gen, send, recv] }`. */
    private fun parseMap(json: String): JSONObject = try {
        JSONObject(json)
    } catch (_: Exception) {
        JSONObject()
    }

    /** Read the recorded high-water mark for a peer, or null when never recorded. */
    fun read(settings: SettingsManager, peer: String): RatchetWatermark? {
        if (peer.isEmpty()) return null
        val map = parseMap(settings.ratchetWatermarkJson)
        val arr = map.optJSONArray(peer) ?: return null
        if (arr.length() != 4) return null
        return try {
            RatchetWatermark(
                pairingEpoch = arr.getLong(0).toULong(),
                ratchetGeneration = arr.getInt(1).toUInt(),
                sendMessageCount = arr.getLong(2).toULong(),
                recvMessageCount = arr.getLong(3).toULong(),
            )
        } catch (_: Exception) {
            null
        }
    }

    /** True when `a` is strictly ahead of `b` in lexicographic 4-tuple order. */
    fun isAhead(a: RatchetWatermark, b: RatchetWatermark): Boolean {
        val av = listOf(
            a.pairingEpoch, a.ratchetGeneration.toULong(), a.sendMessageCount, a.recvMessageCount
        )
        val bv = listOf(
            b.pairingEpoch, b.ratchetGeneration.toULong(), b.sendMessageCount, b.recvMessageCount
        )
        for (i in 0 until 4) {
            if (av[i] > bv[i]) return true
            if (av[i] < bv[i]) return false
        }
        return false
    }

    /**
     * Merge a fresh watermark into the persisted high-water mark (only ever
     * moves forward). Returns the newly stored watermark for the peer, or null
     * when `fresh` is null.
     */
    fun update(settings: SettingsManager, peer: String, fresh: RatchetWatermark?): RatchetWatermark? {
        if (peer.isEmpty() || fresh == null) return null
        val map = parseMap(settings.ratchetWatermarkJson)
        val stored = read(settings, peer)
        val effective = if (stored != null && isAhead(stored, fresh)) stored else fresh
        map.put(peer, org.json.JSONArray().apply {
            put(effective.pairingEpoch.toString())
            put(effective.ratchetGeneration.toString())
            put(effective.sendMessageCount.toString())
            put(effective.recvMessageCount.toString())
        })
        settings.ratchetWatermarkJson = map.toString()
        return effective
    }

    /**
     * Rollback guard for the cold-start restore path (audit #2 follow-up):
     * a snapshot whose watermark is STRICTLY below the recorded high-water mark
     * is a rollback (an older blob restored from backup, or a same-user
     * tamper) and must be refused. Equal = the current snapshot, accepted.
     */
    fun refuseRollback(snapshotWm: RatchetWatermark, recorded: RatchetWatermark?): Boolean {
        if (recorded == null) return false
        return isAhead(recorded, snapshotWm)
    }
}
