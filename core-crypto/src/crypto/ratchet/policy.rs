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
pub(crate) const REKEY_RETRY_TTL_SECS: u64 = 30;

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
/// Audit finding #8: the effective age of every carrier is judged by
/// [`carrier_effective_age`] — the max of the monotonic and the persisted
/// wall-clock elapsed — so a restored carrier whose monotonic stamp was reset
/// to `now` by `from_snapshot` still ages by its persisted wall-clock attach
/// time and does NOT resurrect as "fresh" for the resend path while the
/// encrypt path evicts it (or vice versa). Both consumers share the helper.
pub(crate) fn outgoing_proposal_is_stale(queue: &VecDeque<RekeyCarrier>) -> bool {
    if queue.is_empty() {
        // No live carrier — nothing to evict (a half-committed proposal whose
        // queue was lost is re-staged by encrypt.rs, never evicted here).
        return false;
    }
    let ttl = std::time::Duration::from_secs(INCOMING_REKEY_TTL_SECS);
    queue.iter().all(|c| carrier_effective_age(c) >= ttl)
}
