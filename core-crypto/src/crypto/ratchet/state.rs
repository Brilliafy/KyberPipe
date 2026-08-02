use super::super::{generate_hybrid_keypair, HybridKeyPair, KyberError, RATCHET_REKEY_INTERVAL};
use super::derive::derive_chain_keys_from_root;
use super::tlv::RatchetEncryptedMessage;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A pending outgoing rekey confirmation. Retains the full rekey payload so an
/// unacknowledged proposal can be RE-SENT on a later message (never
/// TTL-auto-committed — committing unacknowledged key material permanently
/// desyncs the peer, see audit finding #1).
#[derive(Clone)]
pub struct RekeyCarrier {
    /// Send-space sequence number of the message that currently carries the
    /// rekey payload. The peer's RekeyAck carries this value back.
    pub carrier_seq: u64,
    /// Wall-clock time the payload was attached. An entry older than
    /// `REKEY_RETRY_TTL` is re-sent (see encrypt.rs).
    pub attached_at: std::time::Instant,
    pub rekey_x25519_pk: Vec<u8>,
    pub rekey_mlkem_pk: Vec<u8>,
    pub rekey_ciphertext: Vec<u8>,
}

/// Post-Quantum Ephemeral Double Ratchet State (Forward Secrecy & Post-Compromise Security)
/// Includes skip-key caching for out-of-order/dropped packet tolerance
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchetState {
    pub root_key: [u8; 32],
    pub sending_chain_key: [u8; 32],
    pub receiving_chain_key: [u8; 32],
    pub send_message_count: u64,
    pub recv_message_count: u64,
    pub our_hybrid_pair: HybridKeyPair,
    pub peer_x25519_pk: Option<[u8; 32]>,
    pub peer_mlkem_pk: Option<Vec<u8>>,
    pub rekey_interval: u64,
    pub ratchet_generation: u32,
    /// Receiving-chain key from the previous ratchet generation. Retained after
    /// a rekey commit so messages the peer sent on the previous generation but
    /// that are still in flight (out-of-order delivery) can still be decrypted
    /// (audit finding #3). The anchor and generation scope the retained chain.
    pub previous_recv_chain_key: Option<[u8; 32]>,
    pub previous_recv_anchor: Option<u64>,
    pub previous_recv_gen: Option<u32>,
    /// Highest sequence number delivered on the previous generation before the
    /// commit (audit finding #7 replay watermark).
    pub previous_recv_highest_delivered: Option<u64>,
    /// ── INCOMING proposal (received rekey payload from the peer). ──
    /// Deriving/committing these does NOT touch our own outgoing proposal.
    /// The peer that sends a rekey payload derives its next sending chain with
    /// label "send-chain-from-rekey" and its next receiving chain with label
    /// "recv-chain-from-rekey". As the *receiver* of that payload we therefore
    /// swap the roles: our next receiving chain is the peer's send chain and
    /// our next sending chain is the peer's recv chain.
    pub pending_root_key: Option<[u8; 32]>,
    pub pending_sending_chain_key: Option<[u8; 32]>,
    pub pending_receiving_chain_key: Option<[u8; 32]>,
    /// Peer public keys to adopt when the incoming proposal is committed.
    /// Deferred until commit so we never encapsulate to a keypair the peer
    /// has not yet swapped into place (avoids the pre-commit lockout window).
    pub pending_peer_x25519_pk: Option<[u8; 32]>,
    pub pending_peer_mlkem_pk: Option<Vec<u8>>,
    /// Bump the generation exactly once when the incoming proposal is committed
    /// (never at derive time) so the nonce domain stays aligned with the peer.
    pub pending_generation_bump: bool,
    /// Receive-space sequence number of the message that carried the rekey
    /// payload. Used as the payload of the RekeyAck so the initiator can match
    /// it against its own send-space confirm queue.
    pub pending_rekey_carrier_seq: Option<u64>,
    /// ── OUTGOING proposal (our own rekey, awaiting peer ACK). ──
    /// Set during ratchet_encrypt; committed by commit_outgoing_rekey() when
    /// the peer's RekeyAck (or TTL fallback) confirms receipt.
    pub outgoing_root_key: Option<[u8; 32]>,
    pub outgoing_sending_chain_key: Option<[u8; 32]>,
    pub outgoing_receiving_chain_key: Option<[u8; 32]>,
    /// Outgoing hybrid keypair for the next ratchet generation.
    /// Swapped into our_hybrid_pair on commit_outgoing_rekey().
    #[zeroize(skip)]
    pub outgoing_hybrid_pair: Option<HybridKeyPair>,
    /// Cached skip keys keyed by (ratchet_generation, seq). Generation-scoped
    /// so keys from the previous generation's receive chain cannot collide with
    /// the current generation's after a rekey commit resets the counters.
    #[zeroize(skip)]
    pub skip_message_keys: Option<HashMap<(u32, u64), Zeroizing<[u8; 32]>>>,
    pub max_skip: usize,
    /// Historical keypairs from previous ratchet generations — kept until peer acknowledges
    /// the new generation by sending a message encrypted under the new chain.
    /// Elements are zeroized when dropped (HybridKeyPair derives ZeroizeOnDrop).
    #[zeroize(skip)]
    pub previous_keypairs: VecDeque<HybridKeyPair>,
    pub max_key_history: usize,
    /// Queue of pending rekey confirmations. Each entry is keyed by the
    /// message sequence number that currently carries the rekey. Entries are
    /// removed when:
    /// (1) the peer sends a REKEY_ACK (explicit protocol confirmation),
    /// (2) the peer sends a regular message from the new chain (implicit confirmation),
    /// or (3) the entry is re-sent after `REKEY_RETRY_TTL` (the payload is
    /// re-attached to a later message — never auto-committed).
    /// Max 2 entries to bound memory.
    #[zeroize(skip)]
    pub rekey_pending_confirm_queue: VecDeque<RekeyCarrier>,
    /// Seen (generation, seq) pairs for replay detection. Generation-scoped so
    /// a previous-generation message cannot be mis-identified as a replay of a
    /// current-generation one after the counters reset on a rekey commit.
    #[zeroize(skip)]
    pub seen_sequence_numbers: std::collections::HashSet<(u32, u64)>,
    /// Set when a rekey is committed during decryption. Caller should send a RekeyAck.
    /// Cleared by take_pending_rekey_ack_seq().
    #[zeroize(skip)]
    pub pending_rekey_ack_seq: Option<u64>,
    /// Whether this side initiated the session. Deterministic tie-break for
    /// the two-sided rekey race: the initiator's proposal always wins, so the
    /// responder cancels its own outgoing proposal when the initiator's is
    /// received (see ratchet_decrypt_with_rekey in decrypt.rs).
    pub is_initiator: bool,
    /// Rekey payload of the pending outgoing proposal, retained for re-send.
    #[zeroize(skip)]
    pub outgoing_rekey_payload: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    /// Cumulative number of sequence positions advanced by explicit resyncs
    /// (`resync_receiving_chain`) over this session's lifetime. Persisted in the
    /// snapshot and capped by `SYNC_MAX_CUMULATIVE` so a compromised peer cannot
    /// force unbounded forward jumps / KDF work (audit finding #4).
    pub resync_forward_total: u64,
}

// ────────────────────────────────────────────────────────────
// Rekey AAD helpers — bind rekey parameters into the AEAD tag
// to prevent attackers from swapping rekey payloads.
// ────────────────────────────────────────────────────────────

/// Build AAD from rekey parameters. Empty if no rekey payload.
pub(crate) fn build_rekey_aad(
    rekey_ciphertext: Option<&[u8]>,
    rekey_x25519_pk: Option<&[u8]>,
    rekey_mlkem_pk: Option<&[u8]>,
) -> Vec<u8> {
    match (rekey_ciphertext, rekey_x25519_pk, rekey_mlkem_pk) {
        (Some(ct), Some(xpk), Some(mpk)) => {
            let mut aad = Vec::with_capacity(32 + mpk.len() + ct.len() + 3);
            aad.push(b'r');
            aad.extend_from_slice(xpk);
            aad.push(b'm');
            aad.extend_from_slice(mpk);
            aad.push(b'c');
            aad.extend_from_slice(ct);
            aad
        }
        _ => Vec::new(),
    }
}

impl DoubleRatchetState {
    /// Initialize a Double Ratchet session from a master shared secret.
    /// Uses two-phase KDF for domain separation between root key and chain keys.
    ///
    /// NOTE: peer_x25519_pk and peer_mlkem_pk start as None. The first rekey
    /// message (at seq == RATCHET_REKEY_INTERVAL) will populate them via
    /// ratchet_decrypt_with_rekey. Until then, DH/KEM rekeying is inactive —
    /// the first 100 messages use symmetric-only ratchet. To enable immediate
    /// post-compromise security, exchange hybrid public keys during the pairing
    /// handshake so both sides can populate peer keys at init time.
    /// Initialize a Double Ratchet session with a FRESH, never-exchanged hybrid
    /// keypair. The fresh keypair is never shared with the peer, so the peer
    /// encapsulates rekey payloads to OUR pairing public keys while we would
    /// decapsulate with this unrelated private key — a guaranteed permanent
    /// desync at the first rekey boundary (audit finding #1).
    ///
    /// Production callers MUST use [`DoubleRatchetState::new_with_keypair`] and
    /// pass their own pairing keypair (the one exchanged out-of-band during the
    /// KEM handshake). This constructor is retained for legacy tests only.
    pub fn new(
        master_shared_secret: &[u8],
        is_initiator: bool,
        peer_x25519_pk: Option<[u8; 32]>,
        peer_mlkem_pk: Option<Vec<u8>>,
    ) -> Result<Self, KyberError> {
        Self::new_with_keypair(
            master_shared_secret,
            is_initiator,
            generate_hybrid_keypair(),
            peer_x25519_pk,
            peer_mlkem_pk,
        )
    }

    /// Initialize a Double Ratchet session from a master shared secret, using
    /// the caller's OWN pairing keypair as the initial identity.
    ///
    /// This is the fix for audit finding #1: the ratchet's DH identity must be
    /// the keypair whose public halves were exchanged during pairing. The peer
    /// encapsulates rekey payloads to our pairing public keys, so we must
    /// decapsulate with the matching pairing private keys — never a fresh,
    /// unexchanged keypair. The private halves stay in Rust on the desktop; on
    /// Android the caller passes the pairing keypair the client already holds.
    pub fn new_with_keypair(
        master_shared_secret: &[u8],
        is_initiator: bool,
        our_hybrid_pair: HybridKeyPair,
        peer_x25519_pk: Option<[u8; 32]>,
        peer_mlkem_pk: Option<Vec<u8>>,
    ) -> Result<Self, KyberError> {
        // Derive a session-unique salt from the shared secret via HKDF.
        // This ensures both sides agree on the same salt without requiring
        // additional exchange — the salt is deterministically derived from
        // the same key material that both sides already share.
        let salt_hk = Hkdf::<Sha256>::new(None, master_shared_secret);
        let mut session_salt = [0u8; 16];
        salt_hk
            .expand(b"kyberpipe-session-salt", &mut session_salt)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        // Phase 1: Extract master seed from shared secret with fresh session salt
        let mut hk_salt = Vec::with_capacity(24);
        hk_salt.extend_from_slice(b"kyberpipe-pq-salt-");
        hk_salt.extend_from_slice(&session_salt);
        let hk = Hkdf::<Sha256>::new(Some(&hk_salt), master_shared_secret);
        let mut master_seed = [0u8; 32];
        hk.expand(b"kyberpipe-master-seed", &mut master_seed)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        // Phase 2: Derive root key with session-specific sub-salt
        let mut root_salt = Vec::with_capacity(24);
        root_salt.extend_from_slice(b"kyberpipe-root-");
        root_salt.extend_from_slice(&session_salt);
        let root_hk = Hkdf::<Sha256>::new(Some(&root_salt), &master_seed);
        let mut root_key = [0u8; 32];
        root_hk
            .expand(b"kyberpipe-root-key", &mut root_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        // Phase 3: Derive chain keys from root key (not from the same KDF context as root)
        let (sending_ck, receiving_ck) = if is_initiator {
            derive_chain_keys_from_root(
                &root_key,
                b"kyberpipe-send-chain",
                b"kyberpipe-recv-chain",
            )?
        } else {
            derive_chain_keys_from_root(
                &root_key,
                b"kyberpipe-recv-chain",
                b"kyberpipe-send-chain",
            )?
        };

        Ok(Self {
            root_key,
            sending_chain_key: sending_ck,
            receiving_chain_key: receiving_ck,
            send_message_count: 0,
            recv_message_count: 0,
            our_hybrid_pair,
            peer_x25519_pk,
            peer_mlkem_pk,
            rekey_interval: RATCHET_REKEY_INTERVAL,
            ratchet_generation: 0,
            previous_recv_chain_key: None,
            previous_recv_anchor: None,
            previous_recv_gen: None,
            previous_recv_highest_delivered: None,
            pending_root_key: None,
            pending_sending_chain_key: None,
            pending_receiving_chain_key: None,
            pending_peer_x25519_pk: None,
            pending_peer_mlkem_pk: None,
            pending_generation_bump: false,
            pending_rekey_carrier_seq: None,
            outgoing_root_key: None,
            outgoing_sending_chain_key: None,
            outgoing_receiving_chain_key: None,
            outgoing_hybrid_pair: None,
            skip_message_keys: Some(HashMap::new()),
            max_skip: 100,
            previous_keypairs: VecDeque::new(),
            max_key_history: 3,
            rekey_pending_confirm_queue: VecDeque::new(),
            seen_sequence_numbers: std::collections::HashSet::new(),
            pending_rekey_ack_seq: None,
            is_initiator,
            outgoing_rekey_payload: None,
            resync_forward_total: 0,
        })
    }

    /// Retain the current receiving chain as the PREVIOUS-generation chain so
    /// in-flight messages from the old generation can still be decrypted after
    /// a rekey commit (audit finding #3). Only the immediately-previous chain is
    /// kept: a rekey cannot be ACKed until the previous one is committed, so the
    /// peer can never be more than one generation ahead in our receive space.
    fn retain_previous_receiving_chain(&mut self) {
        self.previous_recv_chain_key = Some(self.receiving_chain_key);
        self.previous_recv_anchor = Some(self.recv_message_count);
        self.previous_recv_gen = Some(self.ratchet_generation);
        // Audit finding #7: freeze the highest DELIVERED sequence number before
        // the commit clears `seen_sequence_numbers`. A message whose key was
        // cached before the commit (out-of-order delivery) must not be
        // re-derivable from the retained chain after the reset.
        self.previous_recv_highest_delivered = self.capture_previous_recv_watermark();
    }

    /// Highest sequence number delivered on the current generation, used as the
    /// replay watermark for the previous generation after a commit (audit
    /// finding #7). None when nothing has been delivered yet.
    fn capture_previous_recv_watermark(&self) -> Option<u64> {
        let max_seen = self
            .seen_sequence_numbers
            .iter()
            .filter(|(gen, _)| *gen == self.ratchet_generation)
            .map(|(_, seq)| *seq)
            .max();
        let contiguous = self.recv_message_count.saturating_sub(1);
        if self.recv_message_count > 0 {
            Some(match max_seen {
                Some(s) => contiguous.max(s),
                None => contiguous,
            })
        } else {
            max_seen
        }
    }

    /// Reset per-generation counters and caches after a rekey commit. The new
    /// generation's chains start at position 0 on BOTH sides, which makes the
    /// pending-chain anchor deterministic (audit finding #2) and lets the
    /// receiver derive the first new-generation message key from position 0
    /// regardless of how many old-generation messages were still in flight.
    fn reset_generation_counters(&mut self) {
        self.send_message_count = 0;
        self.recv_message_count = 0;
        // Skip keys and seen-seqs are generation-scoped (keyed by generation), so
        // the new generation starts with empty caches.
        if let Some(store) = self.skip_message_keys.as_mut() {
            store.clear();
        }
        self.seen_sequence_numbers.clear();
    }

    /// Commit the INCOMING rekey proposal (derived from a rekey payload sent by
    /// the peer). Atomic full transition: root + both chain keys + peer public
    /// keys + generation bump + carrier/ack bookkeeping. Call only after the
    /// pending chain has authenticated a message (AEAD verified).
    pub fn commit_pending_rekey(&mut self) {
        if let (Some(pk), Some(psk), Some(prk)) = (
            self.pending_root_key,
            self.pending_sending_chain_key,
            self.pending_receiving_chain_key,
        ) {
            // Retain the old receiving chain so late previous-generation messages
            // (in flight when this commit happened) still decrypt.
            self.retain_previous_receiving_chain();
            self.root_key = pk;
            self.sending_chain_key = psk;
            self.receiving_chain_key = prk;
            if let Some(xpk) = self.pending_peer_x25519_pk.take() {
                self.peer_x25519_pk = Some(xpk);
            }
            if let Some(mpk) = self.pending_peer_mlkem_pk.take() {
                self.peer_mlkem_pk = Some(mpk);
            }
            if self.pending_generation_bump {
                self.ratchet_generation = self.ratchet_generation.saturating_add(1);
                self.pending_generation_bump = false;
            }
            self.reset_generation_counters();
        }
        // Always clear the pending slot, even on partial/no-op commit.
        self.pending_root_key = None;
        self.pending_sending_chain_key = None;
        self.pending_receiving_chain_key = None;
        self.pending_peer_x25519_pk = None;
        self.pending_peer_mlkem_pk = None;
        self.pending_generation_bump = false;
        // If we have not yet asked the peer to confirm this proposal, do so now
        // using the recorded carrier sequence (send-space of the rekey message).
        if self.pending_rekey_ack_seq.is_none() {
            self.pending_rekey_ack_seq = self.pending_rekey_carrier_seq;
        }
        self.pending_rekey_carrier_seq = None;
    }

    /// Commit the OUTGOING rekey proposal (our own rekey) once the peer has
    /// acknowledged it. Atomic full transition: root + both chain keys + swap
    /// our hybrid keypair + generation bump.
    pub fn commit_outgoing_rekey(&mut self) {
        if let (Some(ok), Some(osk), Some(ork)) = (
            self.outgoing_root_key,
            self.outgoing_sending_chain_key,
            self.outgoing_receiving_chain_key,
        ) {
            // Retain the old receiving chain: the peer may still send messages on
            // the previous generation while it catches up (audit finding #3).
            self.retain_previous_receiving_chain();
            self.root_key = ok;
            self.sending_chain_key = osk;
            self.receiving_chain_key = ork;
            if let Some(new_pair) = self.outgoing_hybrid_pair.take() {
                let old_pair = std::mem::replace(&mut self.our_hybrid_pair, new_pair);
                // Keep a bounded history of our own old keypairs so rekey payloads
                // the peer encapsulated to our previous public keys (sent before it
                // learned of our commit) can still be decapsulated.
                self.previous_keypairs.push_back(old_pair);
                while self.previous_keypairs.len() > self.max_key_history {
                    self.previous_keypairs.pop_front();
                }
                self.ratchet_generation = self.ratchet_generation.saturating_add(1);
            }
            self.reset_generation_counters();
        }
        self.outgoing_root_key = None;
        self.outgoing_sending_chain_key = None;
        self.outgoing_receiving_chain_key = None;
        self.outgoing_hybrid_pair = None;
        self.outgoing_rekey_payload = None;
    }

    /// Cancel an unacknowledged outgoing proposal. Used by the deterministic
    /// two-sided rekey tie-break: when the initiator's proposal preempts the
    /// responder's, the responder cancels its own and adopts the initiator's.
    pub fn cancel_outgoing_rekey(&mut self) {
        self.outgoing_root_key = None;
        self.outgoing_sending_chain_key = None;
        self.outgoing_receiving_chain_key = None;
        self.outgoing_hybrid_pair = None;
        self.outgoing_rekey_payload = None;
        self.rekey_pending_confirm_queue.clear();
    }

    /// Process a REKEY_ACK from the peer, confirming they have successfully
    /// received and processed a rekey payload.
    /// Take the pending rekey ACK sequence number, clearing it.
    /// Returns None if no ACK is pending.
    ///
    /// Also clears `pending_rekey_carrier_seq`: once the ACK has been handed to
    /// the caller, a later `commit_pending_rekey` must NOT re-queue a duplicate
    /// ACK for the same carrier (the peer ignores stale ACKs, but they are dead
    /// traffic and confuse the ack round-trip logic).
    pub fn take_pending_rekey_ack_seq(&mut self) -> Option<u64> {
        let seq = self.pending_rekey_ack_seq.take();
        self.pending_rekey_carrier_seq = None;
        seq
    }

    /// Process a REKEY_ACK from the peer. `seq` is the send-space sequence
    /// number of the message that carried the rekey (the carrier), matching the
    /// entries pushed into `rekey_pending_confirm_queue` by ratchet_encrypt.
    /// On match, the OUTGOING proposal is committed atomically.
    pub fn process_rekey_ack(&mut self, seq: u64) -> bool {
        let index = self
            .rekey_pending_confirm_queue
            .iter()
            .position(|c| c.carrier_seq == seq);
        if let Some(idx) = index {
            self.rekey_pending_confirm_queue.remove(idx);
            self.commit_outgoing_rekey();
            true
        } else {
            false
        }
    }

    pub fn generate_rekey_ack(&mut self, seq: u64) -> Result<RatchetEncryptedMessage, KyberError> {
        let msg = crate::packets::KyberMessage::RekeyAck { seq };
        self.ratchet_encrypt(msg.to_json()?.as_bytes())
    }

    /// Check if a decrypted message is a rekey ACK.
    pub fn is_rekey_ack(plaintext: &[u8]) -> bool {
        if let Ok(msg) = crate::packets::safe_decode_packet(plaintext) {
            matches!(msg, crate::packets::KyberMessage::RekeyAck { .. })
        } else {
            false
        }
    }
}
