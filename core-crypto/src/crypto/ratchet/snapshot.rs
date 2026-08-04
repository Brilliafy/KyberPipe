//! Persistence DTO: `RatchetSnapshot` + `to_snapshot`/`from_snapshot` (audit
//! finding #11 — extracted from the former `state.rs` monolith so the live
//! state machine, the wire codec (tlv.rs) and the persistence DTO each live in
//! their own module). The caller is responsible for encrypting the serialized
//! bytes (e.g. wrapped by the device/session key) before writing them to disk.

use super::state::{
    Chain, DoubleRatchetState, IncomingProposal, OutgoingProposal, RekeyCarrier, ReplayWindow,
};
use crate::crypto::{HybridKeyPair, RATCHET_REKEY_INTERVAL};
use crate::error::KyberError;
use std::collections::{HashMap, VecDeque};
use zeroize::Zeroizing;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RatchetSnapshot {
    pub root_key: [u8; 32],
    pub sending_chain_key: [u8; 32],
    pub receiving_chain_key: [u8; 32],
    pub send_message_count: u64,
    pub recv_message_count: u64,
    pub our_x25519_pk: [u8; 32],
    pub our_x25519_sk: [u8; 32],
    pub our_mlkem_pk: Vec<u8>,
    pub our_mlkem_sk: Vec<u8>,
    pub peer_x25519_pk: Option<[u8; 32]>,
    pub peer_mlkem_pk: Option<Vec<u8>>,
    pub ratchet_generation: u32,
    /// Pairing epoch watermark (audit finding #2): the import guard refuses to
    /// overlay a snapshot whose epoch differs from the live session's, so a
    /// stale pre-re-pair snapshot can never clobber a freshly re-paired
    /// session. Serde-defaults to 0 for snapshots written before this field
    /// existed.
    #[serde(default)]
    pub pairing_epoch: u64,
    pub pending_root_key: Option<[u8; 32]>,
    pub pending_sending_chain_key: Option<[u8; 32]>,
    pub pending_receiving_chain_key: Option<[u8; 32]>,
    pub pending_peer_x25519_pk: Option<[u8; 32]>,
    pub pending_peer_mlkem_pk: Option<Vec<u8>>,
    pub pending_generation_bump: bool,
    pub pending_rekey_carrier_seq: Option<u64>,
    /// Generation of the message that carried the incoming rekey proposal
    /// (audit F1) — guards the single proposal slot against stale crossed or
    /// re-sent carriers after a restart, matching the in-memory guard.
    pub pending_carrier_gen: Option<u32>,
    pub outgoing_root_key: Option<[u8; 32]>,
    pub outgoing_sending_chain_key: Option<[u8; 32]>,
    pub outgoing_receiving_chain_key: Option<[u8; 32]>,
    pub outgoing_x25519_pk: Option<[u8; 32]>,
    pub outgoing_x25519_sk: Option<[u8; 32]>,
    pub outgoing_mlkem_pk: Option<Vec<u8>>,
    pub outgoing_mlkem_sk: Option<Vec<u8>>,
    pub max_skip: usize,
    pub max_key_history: usize,
    pub previous_x25519_pk: Vec<[u8; 32]>,
    pub previous_x25519_sk: Vec<[u8; 32]>,
    pub previous_mlkem_pk: Vec<Vec<u8>>,
    pub previous_mlkem_sk: Vec<Vec<u8>>,
    pub skip_message_keys: Vec<((u32, u64), [u8; 32])>,
    pub seen_sequence_numbers: Vec<(u32, u64)>,
    /// Receiving chain key from the previous ratchet generation, retained so
    /// in-flight previous-generation messages can still be decrypted after this
    /// side commits a rekey (audit finding #3).
    pub previous_recv_chain_key: Option<[u8; 32]>,
    /// Receive position at which `previous_recv_chain_key` was abandoned.
    pub previous_recv_anchor: Option<u64>,
    /// Generation that `previous_recv_chain_key` belongs to.
    pub previous_recv_gen: Option<u32>,
    /// Highest sequence number DELIVERED on the previous generation before the
    /// rekey commit. Persisted replay watermark: after `seen_sequence_numbers`
    /// is reset by a commit, this rejects replays of already-delivered
    /// previous-generation messages (audit finding #7).
    #[serde(default)]
    pub previous_recv_highest_delivered: Option<u64>,
    /// Pending rekey confirmations (carrier seqs only — timestamps reset on
    /// restore; payloads are reconstructed from `outgoing_rekey_payload`).
    pub rekey_pending_confirm_queue: Vec<u64>,
    /// Wall-clock unix attach time of each pending rekey confirmation, parallel
    /// to `rekey_pending_confirm_queue` (audit finding #8). PERSISTED so a
    /// restored-but-unacked outgoing proposal is still bounded by the retry
    /// TTL instead of resetting to "fresh" on restart — otherwise a stale
    /// proposal resurrects on every process death and re-blocks recovery for
    /// another TTL window. Serde-defaults to empty for snapshots written before
    /// this field existed.
    #[serde(default)]
    pub rekey_pending_confirm_queue_attached_at_unix: Vec<u64>,
    pub pending_rekey_ack_seq: Option<u64>,
    /// Cumulative forward advancement budget consumed by resyncs (audit #4).
    #[serde(default)]
    pub resync_forward_total: u64,
    /// Whether this side initiated the session (desktop = initiator). Used as
    /// the deterministic tie-break for the two-sided rekey race (audit #5):
    /// the initiator's proposal always takes precedence over the responder's.
    #[serde(default)]
    pub is_initiator: bool,
    /// Rekey payload (x25519 pk, mlkem pk, KEM ciphertext) of the pending
    /// outgoing proposal — retained so an unacknowledged proposal can be
    /// re-sent instead of TTL-committed.
    #[serde(default)]
    pub outgoing_rekey_payload: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// Wall-clock unix time the INCOMING proposal was first derived (audit
    /// KYP-2026-02 #3). Persisted so the proposal's bounded lifetime survives
    /// restarts — a stale proposal must not deadlock the Synchronize recovery
    /// path after a process restart.
    #[serde(default)]
    pub pending_proposal_attached_at_unix: Option<u64>,
}

impl DoubleRatchetState {
    /// Serialize the full ratchet state into a storable snapshot.
    pub fn to_snapshot(&self) -> RatchetSnapshot {
        let prev = self.previous_keypairs.iter().collect::<Vec<_>>();
        RatchetSnapshot {
            root_key: self.root_key,
            sending_chain_key: self.send.key,
            receiving_chain_key: self.recv.key,
            send_message_count: self.send.message_count,
            recv_message_count: self.recv.message_count,
            our_x25519_pk: self.our_hybrid_pair.x25519_pk,
            our_x25519_sk: self.our_hybrid_pair.x25519_sk,
            our_mlkem_pk: self.our_hybrid_pair.mlkem_pk.clone(),
            our_mlkem_sk: self.our_hybrid_pair.mlkem_sk.clone(),
            peer_x25519_pk: self.peer_x25519_pk,
            peer_mlkem_pk: self.peer_mlkem_pk.clone(),
            ratchet_generation: self.ratchet_generation,
            pairing_epoch: self.pairing_epoch,
            pending_root_key: self.incoming_proposal.root_key,
            pending_sending_chain_key: self.incoming_proposal.sending_chain_key,
            pending_receiving_chain_key: self.incoming_proposal.receiving_chain_key,
            pending_peer_x25519_pk: self.incoming_proposal.peer_x25519_pk,
            pending_peer_mlkem_pk: self.incoming_proposal.peer_mlkem_pk.clone(),
            pending_generation_bump: self.incoming_proposal.generation_bump,
            pending_rekey_carrier_seq: self.incoming_proposal.carrier_seq,
            pending_carrier_gen: self.incoming_proposal.carrier_gen,
            outgoing_root_key: self.outgoing_proposal.root_key,
            outgoing_sending_chain_key: self.outgoing_proposal.sending_chain_key,
            outgoing_receiving_chain_key: self.outgoing_proposal.receiving_chain_key,
            outgoing_x25519_pk: self
                .outgoing_proposal
                .hybrid_pair
                .as_ref()
                .map(|p| p.x25519_pk),
            outgoing_x25519_sk: self
                .outgoing_proposal
                .hybrid_pair
                .as_ref()
                .map(|p| p.x25519_sk),
            outgoing_mlkem_pk: self
                .outgoing_proposal
                .hybrid_pair
                .as_ref()
                .map(|p| p.mlkem_pk.clone()),
            outgoing_mlkem_sk: self
                .outgoing_proposal
                .hybrid_pair
                .as_ref()
                .map(|p| p.mlkem_sk.clone()),
            max_skip: self.max_skip,
            max_key_history: self.max_key_history,
            previous_x25519_pk: prev.iter().map(|p| p.x25519_pk).collect(),
            previous_x25519_sk: prev.iter().map(|p| p.x25519_sk).collect(),
            previous_mlkem_pk: prev.iter().map(|p| p.mlkem_pk.clone()).collect(),
            previous_mlkem_sk: prev.iter().map(|p| p.mlkem_sk.clone()).collect(),
            skip_message_keys: self
                .skip_message_keys
                .iter()
                .flat_map(|m| m.iter().map(|(k, v)| (*k, **v)))
                .collect(),
            seen_sequence_numbers: self.replay_window.seen.iter().copied().collect(),
            previous_recv_chain_key: self.previous_recv_chain_key,
            previous_recv_anchor: self.previous_recv_anchor,
            previous_recv_gen: self.previous_recv_gen,
            previous_recv_highest_delivered: self.replay_window.prev_gen_highest_delivered,
            rekey_pending_confirm_queue: self
                .rekey_pending_confirm_queue
                .iter()
                .map(|c| c.carrier_seq)
                .collect(),
            rekey_pending_confirm_queue_attached_at_unix: self
                .rekey_pending_confirm_queue
                .iter()
                .map(|c| c.attached_at_unix)
                .collect(),
            pending_rekey_ack_seq: self.pending_rekey_ack_seq,
            is_initiator: self.is_initiator,
            outgoing_rekey_payload: self.outgoing_proposal.rekey_payload.clone(),
            resync_forward_total: self.resync_forward_total,
            pending_proposal_attached_at_unix: self.incoming_proposal.attached_at_unix,
        }
    }

    /// Restore a ratchet state from a snapshot. Timestamps in the confirm queue
    /// are reset to now so TTL-based auto-confirm still functions after restart.
    pub fn from_snapshot(snap: &RatchetSnapshot) -> Result<Self, KyberError> {
        let our_hybrid_pair = HybridKeyPair {
            x25519_pk: snap.our_x25519_pk,
            x25519_sk: snap.our_x25519_sk,
            mlkem_pk: snap.our_mlkem_pk.clone(),
            mlkem_sk: snap.our_mlkem_sk.clone(),
        };
        let mut previous_keypairs = VecDeque::new();
        for i in 0..snap.previous_x25519_pk.len() {
            previous_keypairs.push_back(HybridKeyPair {
                x25519_pk: snap.previous_x25519_pk[i],
                x25519_sk: snap.previous_x25519_sk[i],
                mlkem_pk: snap.previous_mlkem_pk[i].clone(),
                mlkem_sk: snap.previous_mlkem_sk[i].clone(),
            });
        }
        let outgoing_hybrid_pair = match (
            snap.outgoing_x25519_pk,
            snap.outgoing_x25519_sk,
            snap.outgoing_mlkem_pk.clone(),
            snap.outgoing_mlkem_sk.clone(),
        ) {
            (Some(pk), Some(sk), Some(mpk), Some(msk)) => Some(HybridKeyPair {
                x25519_pk: pk,
                x25519_sk: sk,
                mlkem_pk: mpk,
                mlkem_sk: msk,
            }),
            _ => None,
        };
        let mut skip_message_keys = Some(HashMap::new());
        if let Some(store) = skip_message_keys.as_mut() {
            for (k, v) in &snap.skip_message_keys {
                store.insert(*k, Zeroizing::new(*v));
            }
        }
        let now = std::time::Instant::now();
        let now_unix = crate::crypto::ratchet::state::now_unix_secs();
        let queue_len = snap.rekey_pending_confirm_queue.len();
        // Restore each pending confirmation with its PERSISTED wall-clock attach
        // time (audit finding #8) so a stale proposal does not resurrect as
        // "fresh" on restart. When the parallel unix array is absent (a
        // snapshot written by an older build) fall back to the current wall
        // clock — the legacy behavior.
        let mut confirm_attach_unix: Vec<u64> =
            snap.rekey_pending_confirm_queue_attached_at_unix.clone();
        if confirm_attach_unix.len() < queue_len {
            confirm_attach_unix.resize(queue_len, now_unix);
        }
        let mut rekey_pending_confirm_queue: VecDeque<RekeyCarrier> = snap
            .rekey_pending_confirm_queue
            .iter()
            .enumerate()
            .map(|(idx, s)| RekeyCarrier {
                carrier_seq: *s,
                // Monotonic stamp starts at "now" (Instant cannot be restored);
                // the persisted wall-clock `attached_at_unix` below is what
                // keeps the carrier aging across restarts (audit finding #8).
                attached_at: now,
                attached_at_unix: confirm_attach_unix.get(idx).copied().unwrap_or(now_unix),
                rekey_x25519_pk: vec![],
                rekey_mlkem_pk: vec![],
                rekey_ciphertext: vec![],
            })
            .collect();
        // AUDIT #2 (stale-carrier poison): a snapshot written by a build with
        // the old `len() < 2` staging could persist MULTIPLE carriers for one
        // proposal. A restored multi-entry queue is the stale-carrier
        // precondition (one entry survives the peer's ACK and is re-sent with
        // the committed payload under the new generation). Heal it here: keep
        // only the LAST carrier (the most recent re-send, matching the resend
        // semantics) so the restored queue obeys "at most one carrier per
        // pending proposal".
        if rekey_pending_confirm_queue.len() > 1 {
            tracing::warn!(
                "[Ratchet] Snapshot restore: trimming {} stale confirm-queue entries to 1 (audit #2)",
                rekey_pending_confirm_queue.len() - 1
            );
            let last = rekey_pending_confirm_queue.pop_back().expect("non-empty");
            rekey_pending_confirm_queue.clear();
            rekey_pending_confirm_queue.push_back(last);
        }
        // Re-attach the persisted rekey payload to the (single) pending entry,
        // if one was stored. Timestamps are reset to now so the retry TTL
        // starts fresh after a restart.
        if let Some((xpk, mpk, ct)) = snap.outgoing_rekey_payload.clone() {
            if let Some(entry) = rekey_pending_confirm_queue.back_mut() {
                entry.rekey_x25519_pk = xpk;
                entry.rekey_mlkem_pk = mpk;
                entry.rekey_ciphertext = ct;
            }
        }
        let _ = &mut rekey_pending_confirm_queue;
        Ok(Self {
            root_key: snap.root_key,
            send: Chain {
                key: snap.sending_chain_key,
                message_count: snap.send_message_count,
            },
            recv: Chain {
                key: snap.receiving_chain_key,
                message_count: snap.recv_message_count,
            },
            our_hybrid_pair,
            peer_x25519_pk: snap.peer_x25519_pk,
            peer_mlkem_pk: snap.peer_mlkem_pk.clone(),
            rekey_interval: RATCHET_REKEY_INTERVAL,
            ratchet_generation: snap.ratchet_generation,
            pairing_epoch: snap.pairing_epoch,
            previous_recv_chain_key: snap.previous_recv_chain_key,
            previous_recv_anchor: snap.previous_recv_anchor,
            previous_recv_gen: snap.previous_recv_gen,
            replay_window: ReplayWindow {
                seen: snap.seen_sequence_numbers.iter().copied().collect(),
                prev_gen_highest_delivered: snap.previous_recv_highest_delivered,
            },
            incoming_proposal: IncomingProposal {
                root_key: snap.pending_root_key,
                sending_chain_key: snap.pending_sending_chain_key,
                receiving_chain_key: snap.pending_receiving_chain_key,
                peer_x25519_pk: snap.pending_peer_x25519_pk,
                peer_mlkem_pk: snap.pending_peer_mlkem_pk.clone(),
                generation_bump: snap.pending_generation_bump,
                carrier_seq: snap.pending_rekey_carrier_seq,
                carrier_gen: snap.pending_carrier_gen,
                attached_at_unix: snap.pending_proposal_attached_at_unix,
                // Monotonic time cannot survive a restart — the persisted
                // wall-clock bound stands alone (audit finding #10).
                attached_at_mono: None,
            },
            outgoing_proposal: OutgoingProposal {
                root_key: snap.outgoing_root_key,
                sending_chain_key: snap.outgoing_sending_chain_key,
                receiving_chain_key: snap.outgoing_receiving_chain_key,
                hybrid_pair: outgoing_hybrid_pair,
                rekey_payload: snap.outgoing_rekey_payload.clone(),
            },
            skip_message_keys,
            max_skip: snap.max_skip,
            previous_keypairs,
            max_key_history: snap.max_key_history,
            rekey_pending_confirm_queue,
            pending_rekey_ack_seq: snap.pending_rekey_ack_seq,
            is_initiator: snap.is_initiator,
            resync_forward_total: snap.resync_forward_total,
            // Transient (not persisted): the idempotent-peek cache starts empty.
            peeked_ack_cache: None,
        })
    }
}
