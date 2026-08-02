//! Persistence DTO: `RatchetSnapshot` + `to_snapshot`/`from_snapshot` (audit
//! finding #11 — extracted from the former `state.rs` monolith so the live
//! state machine, the wire codec (tlv.rs) and the persistence DTO each live in
//! their own module). The caller is responsible for encrypting the serialized
//! bytes (e.g. wrapped by the device/session key) before writing them to disk.

use super::state::{DoubleRatchetState, RekeyCarrier};
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
    pub pending_root_key: Option<[u8; 32]>,
    pub pending_sending_chain_key: Option<[u8; 32]>,
    pub pending_receiving_chain_key: Option<[u8; 32]>,
    pub pending_peer_x25519_pk: Option<[u8; 32]>,
    pub pending_peer_mlkem_pk: Option<Vec<u8>>,
    pub pending_generation_bump: bool,
    pub pending_rekey_carrier_seq: Option<u64>,
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
}

impl DoubleRatchetState {
    /// Serialize the full ratchet state into a storable snapshot.
    pub fn to_snapshot(&self) -> RatchetSnapshot {
        let prev = self.previous_keypairs.iter().collect::<Vec<_>>();
        RatchetSnapshot {
            root_key: self.root_key,
            sending_chain_key: self.sending_chain_key,
            receiving_chain_key: self.receiving_chain_key,
            send_message_count: self.send_message_count,
            recv_message_count: self.recv_message_count,
            our_x25519_pk: self.our_hybrid_pair.x25519_pk,
            our_x25519_sk: self.our_hybrid_pair.x25519_sk,
            our_mlkem_pk: self.our_hybrid_pair.mlkem_pk.clone(),
            our_mlkem_sk: self.our_hybrid_pair.mlkem_sk.clone(),
            peer_x25519_pk: self.peer_x25519_pk,
            peer_mlkem_pk: self.peer_mlkem_pk.clone(),
            ratchet_generation: self.ratchet_generation,
            pending_root_key: self.pending_root_key,
            pending_sending_chain_key: self.pending_sending_chain_key,
            pending_receiving_chain_key: self.pending_receiving_chain_key,
            pending_peer_x25519_pk: self.pending_peer_x25519_pk,
            pending_peer_mlkem_pk: self.pending_peer_mlkem_pk.clone(),
            pending_generation_bump: self.pending_generation_bump,
            pending_rekey_carrier_seq: self.pending_rekey_carrier_seq,
            outgoing_root_key: self.outgoing_root_key,
            outgoing_sending_chain_key: self.outgoing_sending_chain_key,
            outgoing_receiving_chain_key: self.outgoing_receiving_chain_key,
            outgoing_x25519_pk: self.outgoing_hybrid_pair.as_ref().map(|p| p.x25519_pk),
            outgoing_x25519_sk: self.outgoing_hybrid_pair.as_ref().map(|p| p.x25519_sk),
            outgoing_mlkem_pk: self
                .outgoing_hybrid_pair
                .as_ref()
                .map(|p| p.mlkem_pk.clone()),
            outgoing_mlkem_sk: self
                .outgoing_hybrid_pair
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
            seen_sequence_numbers: self.seen_sequence_numbers.iter().copied().collect(),
            previous_recv_chain_key: self.previous_recv_chain_key,
            previous_recv_anchor: self.previous_recv_anchor,
            previous_recv_gen: self.previous_recv_gen,
            previous_recv_highest_delivered: self.previous_recv_highest_delivered,
            rekey_pending_confirm_queue: self
                .rekey_pending_confirm_queue
                .iter()
                .map(|c| c.carrier_seq)
                .collect(),
            pending_rekey_ack_seq: self.pending_rekey_ack_seq,
            is_initiator: self.is_initiator,
            outgoing_rekey_payload: self.outgoing_rekey_payload.clone(),
            resync_forward_total: self.resync_forward_total,
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
        let mut rekey_pending_confirm_queue: VecDeque<RekeyCarrier> = snap
            .rekey_pending_confirm_queue
            .iter()
            .map(|s| RekeyCarrier {
                carrier_seq: *s,
                attached_at: now,
                rekey_x25519_pk: vec![],
                rekey_mlkem_pk: vec![],
                rekey_ciphertext: vec![],
            })
            .collect();
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
            sending_chain_key: snap.sending_chain_key,
            receiving_chain_key: snap.receiving_chain_key,
            send_message_count: snap.send_message_count,
            recv_message_count: snap.recv_message_count,
            our_hybrid_pair,
            peer_x25519_pk: snap.peer_x25519_pk,
            peer_mlkem_pk: snap.peer_mlkem_pk.clone(),
            rekey_interval: RATCHET_REKEY_INTERVAL,
            ratchet_generation: snap.ratchet_generation,
            previous_recv_chain_key: snap.previous_recv_chain_key,
            previous_recv_anchor: snap.previous_recv_anchor,
            previous_recv_gen: snap.previous_recv_gen,
            previous_recv_highest_delivered: snap.previous_recv_highest_delivered,
            pending_root_key: snap.pending_root_key,
            pending_sending_chain_key: snap.pending_sending_chain_key,
            pending_receiving_chain_key: snap.pending_receiving_chain_key,
            pending_peer_x25519_pk: snap.pending_peer_x25519_pk,
            pending_peer_mlkem_pk: snap.pending_peer_mlkem_pk.clone(),
            pending_generation_bump: snap.pending_generation_bump,
            pending_rekey_carrier_seq: snap.pending_rekey_carrier_seq,
            outgoing_root_key: snap.outgoing_root_key,
            outgoing_sending_chain_key: snap.outgoing_sending_chain_key,
            outgoing_receiving_chain_key: snap.outgoing_receiving_chain_key,
            outgoing_hybrid_pair,
            skip_message_keys,
            max_skip: snap.max_skip,
            previous_keypairs,
            max_key_history: snap.max_key_history,
            rekey_pending_confirm_queue,
            seen_sequence_numbers: snap.seen_sequence_numbers.iter().copied().collect(),
            pending_rekey_ack_seq: snap.pending_rekey_ack_seq,
            is_initiator: snap.is_initiator,
            outgoing_rekey_payload: snap.outgoing_rekey_payload.clone(),
            resync_forward_total: snap.resync_forward_total,
        })
    }
}
