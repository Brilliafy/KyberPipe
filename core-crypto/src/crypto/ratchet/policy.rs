//! Ratchet POLICY surface (audit #2 follow-up — structural decomposition).
//!
//! Extracted from `state.rs` so the `DoubleRatchetState` type stays data +
//! invariants while the policy surface (TTL budgets, replay-window cap, the
//! staleness/eviction predicates that operate on plain fields) lives in one
//! place. Keeping every tunable policy constant here means a future change to
//! a TTL, a replay cap or a retry budget touches one module and cannot drift
//! from the predicates that consume it.

use super::state::{IncomingProposal, RekeyCarrier};
use std::collections::VecDeque;

/// Wall-clock lifetime of an unconsumed INCOMING rekey proposal (audit
/// KYP-2026-02 #3). A proposal the peer has not completed within this window —
/// i.e. no authenticated new-generation message arrived to consume it — is
/// considered STALE: the peer is cut off (the very condition that triggers a
/// Synchronize), so it can never send the messages that would consume the
/// proposal. A stale proposal is EVICTED by the Synchronize recovery path
/// instead of deadlocking it. Persisted across restarts via the snapshot
/// (`pending_proposal_attached_at_unix`) so the bound survives process death.
pub(crate) const INCOMING_REKEY_TTL_SECS: u64 = 60;

/// Maximum entries retained in the replay-window (seen-sequence) set. Bounds
/// memory and the scan cost of the replay check under high throughput.
pub(crate) const SEEN_SET_MAX: usize = 4096;

/// Retry TTL for an unacknowledged outgoing rekey payload. A carrier whose
/// payload has not been acked within this window is RE-SENT on a later message
/// (never TTL-auto-committed — committing unacknowledged key material
/// permanently desyncs the peer).
///
/// AUDIT F3 FIX: lowered 30s → 15s. The bounded latency cost of a LOST
/// carrier (the peer never received the rekey payload, e.g. a dropped packet
/// at the boundary message) is exactly this window: the sender cannot commit
/// and `should_rekey` is blocked by the pending proposal, so the payload is
/// re-attached only on the retry path. 15s halves the recovery time while
/// remaining far below the 60s incoming-proposal staleness TTL, so a re-send
/// can never race the peer's eviction. Re-sends ride messages that advance
/// the chain anyway — no extra chain burn.
pub(crate) const REKEY_RETRY_TTL_SECS: u64 = 15;

/// Current wall-clock time in unix seconds.
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The effective age of a pending rekey carrier, bounded by BOTH clocks
/// (audit finding #8): the MAXIMUM of the monotonic elapsed time and the
/// wall-clock elapsed time. A wall-clock rollback cannot stretch the retry
/// window; a forward jump cannot instantly evict a live carrier. The single
/// helper is used by BOTH consumers — the encrypt-path retry eviction and the
/// resync-path staleness predicate — so the two code paths can never disagree
/// about the same carrier (the finding #8 drift surface). `attached_at_mono`
/// was dead code (redundant with the monotonic `attached_at` stamp) and has
/// been removed.
pub(crate) fn carrier_effective_age(c: &RekeyCarrier) -> std::time::Duration {
    let mono_elapsed = c.attached_at.elapsed();
    let wall_elapsed =
        std::time::Duration::from_secs(now_unix_secs().saturating_sub(c.attached_at_unix));
    mono_elapsed.max(wall_elapsed)
}

/// Effective age of a pending rekey carrier measured from its FIRST staging
/// (AUDIT F2), bounded by both clocks like [`carrier_effective_age`]. Unlike
/// the retry age, the first-attached stamps are NEVER refreshed by re-sends,
/// so this is the honest measure of "how long has the peer had to ACK this
/// proposal". The resync-path staleness predicate uses THIS age; the
/// encrypt-path retry eviction keeps using [`carrier_effective_age`].
pub(crate) fn carrier_first_attached_effective_age(c: &RekeyCarrier) -> std::time::Duration {
    let mono_elapsed = c.first_attached_at.elapsed();
    let wall_elapsed =
        std::time::Duration::from_secs(now_unix_secs().saturating_sub(c.first_attached_at_unix));
    mono_elapsed.max(wall_elapsed)
}

/// Whether the INCOMING proposal has exceeded its bounded lifetime. A proposal
/// with no recorded attach time is treated as fresh (conservative: refuses
/// resync until a TTL has demonstrably elapsed).
///
/// Audit finding #10: the lifetime is bounded by BOTH clocks. The elapsed
/// measurement is the MAXIMUM of the monotonic and wall-clock elapses, so a
/// wall-clock rollback cannot stretch the proposal's life indefinitely and a
/// forward jump cannot instantly evict a live proposal.
pub(crate) fn incoming_proposal_is_stale(p: &IncomingProposal) -> bool {
    let wall_elapsed = match p.attached_at_unix {
        Some(at) => now_unix_secs().saturating_sub(at),
        None => 0,
    };
    let mono_elapsed = match p.attached_at_mono {
        Some(at) => at.elapsed().as_secs(),
        // None after a snapshot restore — the persisted wall-clock bound
        // stands alone (monotonic time cannot survive a restart).
        None => 0,
    };
    wall_elapsed.max(mono_elapsed) >= INCOMING_REKEY_TTL_SECS
}

/// Whether the OUTGOING proposal has exceeded its bounded lifetime. The
/// proposal's confirm-queue entries carry attach timestamps (the last
/// re-send). When every entry has outlived the TTL — i.e. the peer has not
/// acked and no re-send traffic has flowed for the TTL window — the proposal
/// is stale and must not block recovery.
///
/// AUDIT F2: the staleness window is measured from the proposal's FIRST
/// staging (`first_attached_at*`), NOT from the last re-send. The legacy
/// predicate measured [`carrier_effective_age`] — the last re-send — and the
/// encrypt path refreshes that stamp every `REKEY_RETRY_TTL` (30s), so a
/// live-but-unacked proposal whose sender kept producing traffic could never
/// reach the 60s staleness threshold and permanently blocked the Synchronize
/// recovery path (the peer's ACK channel down while its data channel flows).
/// Resend frequency keeps its own budget ([`carrier_effective_age`] vs
/// `REKEY_RETRY_TTL`); the STALENESS predicate judges the unacknowledged
/// window from first staging (bounded by both clocks — a restored carrier
/// whose monotonic stamp was reset to `now` by `from_snapshot` still ages by
/// its persisted wall-clock first-attach time).
pub(crate) fn outgoing_proposal_is_stale(queue: &VecDeque<RekeyCarrier>) -> bool {
    if queue.is_empty() {
        // No live carrier — nothing to evict (a half-committed proposal whose
        // queue was lost is re-staged by encrypt.rs, never evicted here).
        return false;
    }
    let ttl = std::time::Duration::from_secs(INCOMING_REKEY_TTL_SECS);
    queue
        .iter()
        .all(|c| carrier_first_attached_effective_age(c) >= ttl)
}
