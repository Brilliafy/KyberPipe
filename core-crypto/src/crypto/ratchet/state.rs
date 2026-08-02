use super::super::{generate_hybrid_keypair, HybridKeyPair, KyberError, RATCHET_REKEY_INTERVAL};
use super::derive::derive_chain_keys_from_root;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod opt_hex_bytes {
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => hex::decode(&s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

mod opt_hex_bytes_32 {
    use serde::{self, Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let decoded = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if decoded.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes"));
                }
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }
}

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

/// Represents an encrypted ratchet message with optional DH re-key payload.
/// UniFFI Record: nonce and ciphertext are raw byte arrays, no hex encoding.
#[derive(uniffi::Record, serde::Serialize, serde::Deserialize)]
pub struct RatchetEncryptedMessage {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    /// If Some, this message includes a new ephemeral public key for DH ratchet re-key
    #[serde(default, deserialize_with = "opt_hex_bytes_32::deserialize")]
    pub rekey_x25519_pk: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "opt_hex_bytes::deserialize")]
    pub rekey_mlkem_pk: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "opt_hex_bytes::deserialize")]
    pub rekey_ciphertext: Option<Vec<u8>>,
}

/// Binary TLV framing for `RatchetEncryptedMessage` (audit finding #12). This
/// is the single cross-platform serialization contract for ratchet payloads —
/// length-prefixed fields, no hex-in-JSON drift surface, ~2x smaller than hex.
///
/// Layout (all lengths big-endian u32):
/// ```text
/// [1B version=0x01][1B has_rekey]
/// [4B nonce_len][nonce]
/// [4B ct_len][ct]
/// [4B rekey_x_len][rekey_x]   (only if has_rekey)
/// [4B rekey_m_len][rekey_m]   (only if has_rekey)
/// [4B rekey_ct_len][rekey_ct] (only if has_rekey)
/// ```
impl RatchetEncryptedMessage {
    pub fn to_binary(&self) -> Result<Vec<u8>, KyberError> {
        let has_rekey = self.rekey_x25519_pk.is_some()
            || self.rekey_mlkem_pk.is_some()
            || self.rekey_ciphertext.is_some();
        let mut buf = Vec::with_capacity(6 + self.nonce.len() + self.ciphertext.len() + 48);
        buf.push(0x01); // version
        buf.push(has_rekey as u8);
        buf.extend_from_slice(&(self.nonce.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&(self.ciphertext.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.ciphertext);
        if has_rekey {
            for field in [
                self.rekey_x25519_pk.as_deref(),
                self.rekey_mlkem_pk.as_deref(),
                self.rekey_ciphertext.as_deref(),
            ] {
                match field {
                    Some(bytes) => {
                        buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                        buf.extend_from_slice(bytes);
                    }
                    // A rekey payload is all-or-nothing; treat a missing field
                    // as zero-length so the decoder stays in sync.
                    None => buf.extend_from_slice(&0u32.to_be_bytes()),
                }
            }
        }
        Ok(buf)
    }

    pub fn from_binary(data: &[u8]) -> Result<Self, KyberError> {
        let mut cursor = 0usize;
        let mut take = |n: usize, what: &str| -> Result<&[u8], KyberError> {
            if data.len() < cursor + n {
                return Err(KyberError::SerializationError(format!(
                    "Ratchet TLV truncated at {what}"
                )));
            }
            let slice = &data[cursor..cursor + n];
            cursor += n;
            Ok(slice)
        };
        let version = take(1, "version")?[0];
        if version != 0x01 {
            return Err(KyberError::SerializationError(format!(
                "Unsupported ratchet TLV version {version}"
            )));
        }
        let has_rekey = take(1, "has_rekey")?[0] != 0;
        let mut read_bytes = |what: &str| -> Result<Vec<u8>, KyberError> {
            let len = u32::from_be_bytes(take(4, what)?.try_into().unwrap()) as usize;
            Ok(take(len, what)?.to_vec())
        };
        let nonce = read_bytes("nonce")?;
        let ciphertext = read_bytes("ciphertext")?;
        let (rekey_x25519_pk, rekey_mlkem_pk, rekey_ciphertext) = if has_rekey {
            (
                Some(read_bytes("rekey_x")?),   
                Some(read_bytes("rekey_m")?),   
                Some(read_bytes("rekey_ct")?),  
            )
        } else {
            (None, None, None)
        };
        Ok(Self {
            nonce,
            ciphertext,
            rekey_x25519_pk,
            rekey_mlkem_pk,
            rekey_ciphertext,
        })
    }
}

/// Serializable snapshot of a DoubleRatchetState for persistence across
/// restarts. The caller is responsible for encrypting the serialized bytes
/// (e.g. wrapped by the device/session key) before writing them to disk.
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
            outgoing_x25519_pk: self
                .outgoing_hybrid_pair
                .as_ref()
                .map(|p| p.x25519_pk),
            outgoing_x25519_sk: self
                .outgoing_hybrid_pair
                .as_ref()
                .map(|p| p.x25519_sk),
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
