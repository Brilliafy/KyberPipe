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
 * AUDIT #1 (HIGH, one-sided rollback): comparisons are COMPONENT-WISE, never
 * lexicographic — the legacy lexicographic order let the send chain's lead
 * mask a recv-chain regression (live send=0/recv=100 vs snapshot
 * send=50/recv=0 was accepted, rolling the receiving chain back). The Rust
 * registry guard, this store and the desktop store all share the same
 * partial order, so no caller can re-derive a divergent interpretation.
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

    /**
     * True when `a` strictly DOMINATES `b` component-wise: at least as
     * advanced in every component (epoch, generation, send, recv) and
     * strictly more advanced in at least one. This is a PARTIAL order — a
     * watermark ahead in send but behind in recv is INCOMPARABLE with one
     * ahead in recv but behind in send, and the rollback guard refuses that
     * situation too (audit #1).
     */
    fun isAhead(a: RatchetWatermark, b: RatchetWatermark): Boolean =
        a.pairingEpoch >= b.pairingEpoch &&
            a.ratchetGeneration >= b.ratchetGeneration &&
            a.sendMessageCount >= b.sendMessageCount &&
            a.recvMessageCount >= b.recvMessageCount &&
            a != b

    /** Same-epoch component-wise dominance or equality (audit #1). */
    private fun dominates(a: RatchetWatermark, b: RatchetWatermark): Boolean =
        a.ratchetGeneration >= b.ratchetGeneration &&
            a.sendMessageCount >= b.sendMessageCount &&
            a.recvMessageCount >= b.recvMessageCount

    /**
     * Merge a fresh watermark into the persisted high-water mark. Only ever
     * moves the mark forward. A snapshot from a NEWER pairing epoch (re-pair:
     * counters reset) supersedes the old epoch wholesale; within one epoch the
     * mark is the component-wise MAX so a send-chain lead can never mask a
     * recv-chain regression (or vice versa — audit #1). Returns the newly
     * stored watermark for the peer, or null when `fresh` is null.
     */
    fun update(settings: SettingsManager, peer: String, fresh: RatchetWatermark?): RatchetWatermark? {
        if (peer.isEmpty() || fresh == null) return null
        val map = parseMap(settings.ratchetWatermarkJson)
        val stored = read(settings, peer)
        val effective = when {
            stored == null -> fresh
            fresh.pairingEpoch > stored.pairingEpoch -> fresh
            fresh.pairingEpoch < stored.pairingEpoch -> stored
            dominates(fresh, stored) -> fresh
            dominates(stored, fresh) -> stored
            // Incomparable within one epoch (send vs recv divergence): merge to
            // the component-wise envelope so neither chain's lead is lost.
            else -> RatchetWatermark(
                pairingEpoch = stored.pairingEpoch,
                ratchetGeneration = maxOf(stored.ratchetGeneration, fresh.ratchetGeneration),
                sendMessageCount = maxOf(stored.sendMessageCount, fresh.sendMessageCount),
                recvMessageCount = maxOf(stored.recvMessageCount, fresh.recvMessageCount),
            )
        }
        map.put(peer, org.json.JSONArray().apply {
            // AUDIT F10 FIX: write RAW NUMBERS, not strings. The desktop store
            // persists `[epoch, gen, send, recv]` as JSON numbers; the legacy
            // `.toString()` here stored strings, a cross-platform wire drift
            // that a stricter parser (or a >i64 epoch) would break. Numbers
            // mirror the desktop contract exactly.
            put(effective.pairingEpoch.toLong())
            put(effective.ratchetGeneration.toLong())
            put(effective.sendMessageCount.toLong())
            put(effective.recvMessageCount.toLong())
        })
        settings.ratchetWatermarkJson = map.toString()
        return effective
    }

    /**
     * Rollback guard for the cold-start restore path (audit #2 follow-up +
     * AUDIT #1). A snapshot is refused when it would regress the recorded
     * high-water mark in ANY component: a snapshot from an OLDER pairing
     * epoch is stale (refuse); a SAME-epoch snapshot that is behind in
     * generation, send OR recv is a rollback (refuse). A snapshot from a
     * NEWER epoch (re-pair, counters reset) is accepted. Equal = the current
     * snapshot, accepted.
     */
    fun refuseRollback(snapshotWm: RatchetWatermark, recorded: RatchetWatermark?): Boolean {
        if (recorded == null) return false
        if (snapshotWm.pairingEpoch != recorded.pairingEpoch) {
            return snapshotWm.pairingEpoch < recorded.pairingEpoch
        }
        return !dominates(snapshotWm, recorded) && snapshotWm != recorded
    }
}
