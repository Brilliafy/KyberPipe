package org.kyberpipe.client.utils

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.core_crypto.RatchetWatermark

/**
 * JVM behavioral tests for the ratchet rollback watermark (finding #2
 * follow-up, Android side). The lexicographic ordering and the restore-time
 * rollback refusal are pure functions — they run hermetically without an
 * emulator and pin the exact semantics the desktop store + Rust registry
 * guard enforce (an import/restore of a snapshot whose watermark is strictly
 * BELOW the recorded high-water mark must be refused; equal = the current
 * snapshot, accepted).
 */
class RatchetWatermarkTest {

    private fun wm(epoch: ULong, gen: UInt, send: ULong, recv: ULong) =
        RatchetWatermark(
            pairingEpoch = epoch,
            ratchetGeneration = gen,
            sendMessageCount = send,
            recvMessageCount = recv,
        )

    /** Lexicographic ordering over (epoch, gen, SEND, recv) — send-aware. */
    @Test
    fun isAheadIsLexicographicAndSendAware() {
        // Same epoch/gen/recv, but live SEND > snapshot SEND → ahead (the
        // exact case the OLD guard got wrong — it compared only gen+recv).
        assertTrue(
            wm(0u, 0u, 5u, 0u).let { it } isAheadOf wm(0u, 0u, 2u, 0u)
        )
        // Generation dominates.
        assertTrue(wm(0u, 1u, 0u, 0u) isAheadOf wm(0u, 0u, 999u, 999u))
        // Epoch dominates.
        assertTrue(wm(1u, 0u, 0u, 0u) isAheadOf wm(0u, 5u, 999u, 999u))
        // Equal → NOT ahead.
        assertFalse(wm(0u, 0u, 5u, 0u) isAheadOf wm(0u, 0u, 5u, 0u))
        // recv is the last tiebreak.
        assertTrue(wm(0u, 0u, 5u, 3u) isAheadOf wm(0u, 0u, 5u, 2u))
    }

    /** Restore refuses a snapshot STRICTLY below the recorded high-water mark. */
    @Test
    fun refuseRollbackRejectsOlderSnapshotAndAcceptsEqual() {
        val recorded = wm(0u, 2u, 105u, 102u)
        // Older snapshot (same gen, fewer send) → rollback → refuse.
        assertTrue(RatchetWatermarkStore.refuseRollback(wm(0u, 2u, 100u, 99u), recorded))
        // Equal (the current snapshot after a normal restart) → accepted.
        assertFalse(RatchetWatermarkStore.refuseRollback(wm(0u, 2u, 105u, 102u), recorded))
        // No recorded mark → accepted (first import).
        assertFalse(RatchetWatermarkStore.refuseRollback(wm(0u, 0u, 1u, 1u), null))
        // Higher watermark (a re-pair epoch bump) → accepted.
        assertFalse(RatchetWatermarkStore.refuseRollback(wm(1u, 0u, 0u, 0u), recorded))
    }

    private infix fun RatchetWatermark.isAheadOf(other: RatchetWatermark): Boolean =
        RatchetWatermarkStore.isAhead(this, other)
}
