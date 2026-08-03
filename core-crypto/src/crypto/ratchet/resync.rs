//! Receive-chain RESYNC module (audit F19 split): skip-key helpers, the
//! Synchronize budget/TTL policy and `resync_receiving_chain` were extracted
//! from the former `decrypt.rs` monolith so the dispatch table, the
//! previous-generation path and the recovery path each live in their own module.

use super::state::{DoubleRatchetState, INCOMING_REKEY_TTL_SECS};
use crate::error::KyberError;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Maximum forward gap a Synchronize resync will re-derive. Bounds the KDF
/// work an authenticated peer can request (anti-DoS).
pub(crate) const SYNC_MAX_GAP: u64 = 1000;
/// Cumulative forward-advance budget a session may consume across its whole
/// lifetime via explicit resyncs. Persisted in the snapshot (audit finding #4:
/// without a high-water mark a compromised peer can force unbounded forward
/// jumps that irreversibly discard skip keys and burn CPU).
pub(crate) const SYNC_MAX_CUMULATIVE: u64 = 20_000;

/// Skip-key map type: (generation, seq) → zeroizing message key.
pub(crate) type SkipKeyMap = std::collections::HashMap<(u32, u64), Zeroizing<[u8; 32]>>;
/// Result of a single chain advancement: the next chain key plus the derived
/// skip-key map.
pub(crate) type AdvanceResult = ([u8; 32], SkipKeyMap);

/// Single-pass state advancement for pending chain fallback.
/// After AEAD verification on the pending chain, advances recv_message_count
/// and derives skip keys in one pass — eliminates the double-decrypt pattern.
/// Returns (next_chain_key_for_seq+1, skip_keys_map).
///
/// `base_seq` is the chain position the provided chain key is anchored at. For
/// the pending (post-commit) chain this is 0: rekey commits reset the per-
/// generation counters on BOTH sides (audit finding #2), so the first
/// new-generation message is always at chain position 0.
pub(crate) fn advance_receiving_chain(
    recv_chain_key: &[u8; 32],
    base_seq: u64,
    target_seq: u64,
    generation: u32,
    max_skip: usize,
) -> Result<AdvanceResult, KyberError> {
    if target_seq > base_seq {
        let diff = (target_seq - base_seq) as usize;
        if diff > max_skip {
            return Err(KyberError::SessionDesynchronized(format!(
                "Sequence gap {} exceeds max_skip {}",
                diff, max_skip
            )));
        }
    }
    // Audit finding #18: chain keys and message keys are secret material —
    // derive and transport them in Zeroizing buffers so error paths and drops
    // cannot leave them in freed heap/stack memory.
    let mut ck: Zeroizing<[u8; 32]> = Zeroizing::new(*recv_chain_key);
    let mut skip_keys: SkipKeyMap = std::collections::HashMap::new();
    for skip_seq in base_seq..target_seq {
        let hk = Hkdf::<Sha256>::new(Some(&*ck), b"step");
        let mut skip_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        hk.expand(b"kyberpipe-msg-key", &mut *skip_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-chain", &mut *ck)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        skip_keys.insert((generation, skip_seq), skip_key);
    }
    // The chain for the message AFTER `target_seq` is derived by stepping the
    // chain key once more. The previous implementation derived a msg-key here,
    // which desynchronized the very next message after a pending-chain commit.
    let hk = Hkdf::<Sha256>::new(Some(&*ck), b"step");
    let mut next_ck: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    hk.expand(b"kyberpipe-next-chain", &mut *next_ck)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
    Ok((*next_ck, skip_keys))
}

/// Bound the in-memory skip-key cache. Generation-scoped keys let us evict the
/// oldest generation first, then the lowest seq within the current one.
pub(crate) fn prune_skip_keys(
    store: &mut HashMap<(u32, u64), Zeroizing<[u8; 32]>>,
    current_gen: u32,
    budget: usize,
) {
    // First evict any stale generation that is not the current or previous one.
    store.retain(|&(gen, _), _| {
        gen == current_gen
            || (current_gen > 0 && gen == current_gen - 1)
            || (current_gen == u32::MAX && gen == u32::MAX)
    });
    while store.len() > budget {
        let oldest = *store.keys().min().unwrap_or(&(0, 0));
        store.remove(&oldest);
    }
}

impl DoubleRatchetState {
    /// Explicit session resync after a gap exceeded `max_skip` (e.g. a Wi-Fi →
    /// cellular handoff dropped a burst of messages). Derives skip keys for the
    /// missed range and advances the receiving chain to `target_seq`.
    ///
    /// SECURITY (audit finding #4):
    /// - The Synchronize request MUST already have been authenticated by the
    ///   caller (ratchet-decrypted and verified as a `KyberMessage::Synchronize`).
    /// - Refuses to resync across an unconsumed pending rekey: deriving keys
    ///   across a generation boundary from the current chain key yields garbage.
    /// - Bounds the forward gap per call (SYNC_MAX_GAP) and the cumulative
    ///   advancement across the session lifetime (SYNC_MAX_CUMULATIVE, persisted)
    ///   so a compromised peer cannot force unbounded forward jumps.
    pub fn resync_receiving_chain(&mut self, target_seq: u64) -> Result<u64, KyberError> {
        // Audit KYP-2026-02 #3: an unconsumed rekey proposal must NOT deadlock
        // the recovery path forever. A proposal that exceeds its bounded
        // lifetime (`INCOMING_REKEY_TTL_SECS`, persisted across restarts) is
        // STALE: the peer is cut off — the very condition that triggered the
        // Synchronize — so it can never send the new-generation messages that
        // would consume the proposal, and the sender's own confirm queue can
        // never complete either (the sender cannot commit without our ACK).
        // A stale proposal is EVICTED first so the resync is attempted, never
        // blocked by it. Only a FRESH proposal (one the peer may still be
        // actively completing) refuses the resync — jumping the chain across a
        // live generation boundary would derive garbage keys.
        if self.incoming_proposal.root_key.is_some()
            || self.incoming_proposal.receiving_chain_key.is_some()
        {
            if self.incoming_proposal_is_stale() {
                tracing::warn!(
                    "[Sync] Evicting stale incoming rekey proposal (TTL {}s) to unblock recovery",
                    INCOMING_REKEY_TTL_SECS
                );
                self.cancel_pending_incoming_rekey();
            } else {
                return Err(KyberError::CryptoError(
                    "Synchronize refused: a fresh unconsumed rekey proposal is pending — resolve it first"
                        .into(),
                ));
            }
        }
        if self.outgoing_proposal.root_key.is_some()
            || self.outgoing_proposal.sending_chain_key.is_some()
        {
            if self.outgoing_proposal_is_stale() {
                tracing::warn!(
                    "[Sync] Evicting stale outgoing rekey proposal (TTL {}s) to unblock recovery",
                    INCOMING_REKEY_TTL_SECS
                );
                self.cancel_outgoing_rekey();
            } else {
                return Err(KyberError::CryptoError(
                    "Synchronize refused: a fresh unconsumed outgoing rekey proposal is pending — resolve it first"
                        .into(),
                ));
            }
        }
        let cur = self.recv.message_count;
        if target_seq <= cur {
            return Err(KyberError::CryptoError(format!(
                "Stale Synchronize target {target_seq} (already at {cur})"
            )));
        }
        let gap = target_seq - cur;
        if gap > SYNC_MAX_GAP {
            return Err(KyberError::CryptoError(format!(
                "Synchronize gap {gap} exceeds maximum {SYNC_MAX_GAP} — session must be re-paired"
            )));
        }
        if self.resync_forward_total.saturating_add(gap) > SYNC_MAX_CUMULATIVE {
            return Err(KyberError::CryptoError(format!(
                "Synchronize budget exhausted (cumulative {} + gap {gap} > {SYNC_MAX_CUMULATIVE}) — session must be re-paired",
                self.resync_forward_total
            )));
        }
        // Audit finding #18: derived skip/chain keys live in Zeroizing buffers.
        let mut ck: Zeroizing<[u8; 32]> = Zeroizing::new(self.recv.key);
        let mut skip_keys: HashMap<(u32, u64), Zeroizing<[u8; 32]>> = HashMap::new();
        for skip_seq in cur..target_seq {
            let hk = Hkdf::<Sha256>::new(Some(&*ck), b"step");
            let mut skip_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
            hk.expand(b"kyberpipe-msg-key", &mut *skip_key)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            hk.expand(b"kyberpipe-next-chain", &mut *ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            skip_keys.insert((self.ratchet_generation, skip_seq), skip_key);
        }
        // After skipping `cur..target_seq`, the chain is positioned at
        // `target_seq` — the first non-missed message decrypts from here, so the
        // receiving chain key stays at `ck` and recv_message_count = target_seq.
        self.recv.key = *ck;
        self.recv.message_count = target_seq;
        self.resync_forward_total = self.resync_forward_total.saturating_add(gap);
        let store = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;
        for (k, v) in skip_keys {
            store.insert(k, v);
        }
        prune_skip_keys(store, self.ratchet_generation, self.max_skip * 2);
        Ok(gap)
    }
}
