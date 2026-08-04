//! Ratchet POLICY surface (audit #2 follow-up — structural decomposition).
//!
//! Extracted from `state.rs` so the `DoubleRatchetState` type stays data +
//! invariants while the policy surface (TTL budgets, replay-window cap, the
//! staleness/eviction predicates that operate on plain fields) lives in one
//! place. Keeping every tunable policy constant here means a future change to
//! a TTL, a replay cap or a retry budget touches one module and cannot drift
//! from the predicates that consume it.

use super::state::IncomingProposal;
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
pub(crate) const REKEY_RETRY_TTL_SECS: u64 = 30;

/// Current wall-clock time in unix seconds.
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
/// Audit finding #8: a restored-but-unacked proposal (queue entries present,
/// no re-send has flowed since restart) must NOT be evicted. The monotonic
/// `attached_at` is reset on restore, so staleness here is judged by the
/// persisted wall-clock `attached_at_unix` (which survives restart) and the
/// monotonic clock is used only as a floor: the effective age is the max of
/// both, exactly like the incoming TTL (audit finding #10).
pub(crate) fn outgoing_proposal_is_stale(queue: &VecDeque<super::state::RekeyCarrier>) -> bool {
    if queue.is_empty() {
        // No live carrier — nothing to evict (a half-committed proposal whose
        // queue was lost is re-staged by encrypt.rs, never evicted here).
        return false;
    }
    let now_unix = now_unix_secs();
    queue.iter().all(|c| {
        let wall_elapsed = now_unix.saturating_sub(c.attached_at_unix);
        let mono_elapsed = c.attached_at.elapsed().as_secs();
        wall_elapsed.max(mono_elapsed)
            >= std::time::Duration::from_secs(INCOMING_REKEY_TTL_SECS).as_secs()
    })
}
