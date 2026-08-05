package org.kyberpipe.client.utils

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.core_crypto.RatchetWatermark

/**
 * JVM behavioral tests for the ratchet rollback watermark (finding #2
 * follow-up + AUDIT #1, Android side). The COMPONENT-WISE ordering and the
 * restore-time rollback refusal are pure functions — they run hermetically
 * without an emulator and pin the exact semantics the desktop store + Rust
 * registry guard enforce: an import/restore of a snapshot that regresses the
 * recorded high-water mark in ANY component must be refused (equal = the
 * current snapshot, accepted; a newer pairing epoch = re-pair, accepted).
 */
class RatchetWatermarkTest {

    private fun wm(epoch: ULong, gen: UInt, send: ULong, recv: ULong) =
        RatchetWatermark(
            pairingEpoch = epoch,
            ratchetGeneration = gen,
            sendMessageCount = send,
            recvMessageCount = recv,
        )

    /** Component-wise dominance over (epoch, gen, SEND, recv) — audit #1. */
    @Test
    fun isAheadIsComponentWiseAndSendAware() {
        // Same epoch/gen/recv, but live SEND > snapshot SEND → ahead (the
        // exact case the OLD guard got wrong — it compared only gen+recv).
        assertTrue(
            wm(0u, 0u, 5u, 0u).let { it } isAheadOf wm(0u, 0u, 2u, 0u)
        )
        // recv is not a masked tiebreak either.
        assertTrue(wm(0u, 0u, 5u, 3u) isAheadOf wm(0u, 0u, 5u, 2u))
        // Ahead in EVERY component.
        assertTrue(wm(0u, 1u, 2u, 2u) isAheadOf wm(0u, 0u, 1u, 1u))
        // Equal → NOT ahead.
        assertFalse(wm(0u, 0u, 5u, 0u) isAheadOf wm(0u, 0u, 5u, 0u))

        // AUDIT #1: a one-sided lead is NOT dominance — the exact case the
        // legacy lexicographic order got wrong. Ahead in send but BEHIND in
        // recv must NOT be judged "ahead" (it would mask a recv rollback).
        assertFalse(wm(0u, 0u, 50u, 0u) isAheadOf wm(0u, 0u, 0u, 100u))
        // Ahead in gen but BEHIND in send: incomparable, not ahead.
        assertFalse(wm(0u, 1u, 0u, 0u) isAheadOf wm(0u, 0u, 999u, 999u))
        // Ahead in epoch but BEHIND in gen: incomparable, not ahead.
        assertFalse(wm(1u, 0u, 0u, 0u) isAheadOf wm(0u, 5u, 999u, 999u))
    }

    /** Restore refuses a snapshot that regresses the recorded mark in ANY component. */
    @Test
    fun refuseRollbackRejectsOlderSnapshotAndAcceptsEqual() {
        val recorded = wm(0u, 2u, 105u, 102u)
        // Older snapshot (same gen, fewer send) → rollback → refuse.
        assertTrue(RatchetWatermarkStore.refuseRollback(wm(0u, 2u, 100u, 99u), recorded))
        // AUDIT #1: ahead in send but BEHIND in recv → rollback → refuse.
        assertTrue(RatchetWatermarkStore.refuseRollback(wm(0u, 2u, 150u, 0u), recorded))
        // AUDIT #1: behind in gen even with larger send/recv → refuse.
        assertTrue(RatchetWatermarkStore.refuseRollback(wm(0u, 1u, 999u, 999u), recorded))
        // Equal (the current snapshot after a normal restart) → accepted.
        assertFalse(RatchetWatermarkStore.refuseRollback(wm(0u, 2u, 105u, 102u), recorded))
        // Ahead in every component → accepted (forward snapshot).
        assertFalse(RatchetWatermarkStore.refuseRollback(wm(0u, 3u, 200u, 200u), recorded))
        // No recorded mark → accepted (first import).
        assertFalse(RatchetWatermarkStore.refuseRollback(wm(0u, 0u, 1u, 1u), null))
        // Newer pairing epoch (re-pair, counters reset) → accepted.
        assertFalse(RatchetWatermarkStore.refuseRollback(wm(1u, 0u, 0u, 0u), recorded))
        // Older pairing epoch (stale pre-re-pair snapshot) → refused even with
        // LARGER counters.
        assertTrue(RatchetWatermarkStore.refuseRollback(wm(0u, 5u, 999u, 999u), wm(1u, 0u, 0u, 0u)))
    }

    private infix fun RatchetWatermark.isAheadOf(other: RatchetWatermark): Boolean =
        RatchetWatermarkStore.isAhead(this, other)
}
