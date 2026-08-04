use super::super::{generate_hybrid_keypair, HybridKeyPair, KyberError, RATCHET_REKEY_INTERVAL};
use super::derive::derive_chain_keys_from_root;
use super::resync::SkipKeyMap;
use super::tlv::RatchetEncryptedMessage;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Policy constants (rekey TTLs, replay-window cap) and the staleness/eviction
/// predicates now live in `super::policy` (audit #2 follow-up — structural
/// decomposition). `state.rs` stays data + invariants; the tunable budget
/// surface owns a single module. Re-exported here so existing
/// `super::state::now_unix_secs()` / `INCOMING_REKEY_TTL_SECS` call sites keep
/// resolving unchanged.
pub(crate) use super::policy::{INCOMING_REKEY_TTL_SECS, SEEN_SET_MAX, now_unix_secs};

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
    /// Monotonic attach time. NOT persisted (Instant is not serializable);
    /// restored carriers fall back to [`attached_at_unix`]. Bounds the retry
    /// TTL by BOTH clocks: a wall-clock rollback cannot stretch the retry
    /// window (audit finding #10).
    pub attached_at_mono: std::time::Instant,
    /// Wall-clock unix seconds the payload was attached. PERSISTED in the
    /// snapshot so a restored (never re-sent, never acked) carrier is still
    /// bounded by the TTL instead of resetting to "fresh" on restart (audit
    /// finding #8).
    pub attached_at_unix: u64,
    pub rekey_x25519_pk: Vec<u8>,
    pub rekey_mlkem_pk: Vec<u8>,
    pub rekey_ciphertext: Vec<u8>,
}

/// A single ratchet chain — a KDF chain key plus its message-position counter.
/// Grouped (audit KYP-2026-02 #24) so the send/recv chain invariants (a chain
/// a chain key always advances with its counter) are carried in one unit, and a chain
/// can never be advanced without its key.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Default)]
pub struct Chain {
    pub key: [u8; 32],
    pub message_count: u64,
}

/// The single INCOMING rekey proposal slot (received from the peer). Grouped
/// (audit KYP-2026-02 #24) so the invariant "at most one unconsumed incoming
/// proposal" is enforced by the type: all fields are derived, committed or
/// cancelled together, never one at a time.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Default)]
pub struct IncomingProposal {
    pub root_key: Option<[u8; 32]>,
    pub sending_chain_key: Option<[u8; 32]>,
    pub receiving_chain_key: Option<[u8; 32]>,
    /// Peer public keys to adopt when the incoming proposal is committed.
    /// Deferred until commit so we never encapsulate to a keypair the peer
    /// has not yet swapped into place (avoids the pre-commit lockout window).
    pub peer_x25519_pk: Option<[u8; 32]>,
    pub peer_mlkem_pk: Option<Vec<u8>>,
    /// Bump the generation exactly once when the incoming proposal is committed
    /// (never at derive time) so the nonce domain stays aligned with the peer.
    pub generation_bump: bool,
    /// Receive-space sequence number of the message that carried the rekey
    /// payload. Used as the payload of the RekeyAck so the initiator can match
    /// it against its own send-space confirm queue.
    pub carrier_seq: Option<u64>,
    /// Ratchet generation of the message that carried the rekey payload
    /// (audit F1). Phase 1 derives the proposal under the CURRENT root key;
    /// a carrier from an already-superseded generation (or an older re-send of
    /// the same generation) would stage a proposal derived under the wrong
    /// root and poison the single incoming-proposal slot. Refusing derivation
    /// when `carrier_gen < ratchet_generation` (or older than the pending
    /// proposal's own carrier_gen) keeps a stale crossed/re-sent carrier from
    /// ever touching the slot.
    pub carrier_gen: Option<u32>,
    /// Wall-clock unix time this proposal was first derived (audit
    /// KYP-2026-02 #3). Bounds the proposal's lifetime so a stale proposal can
    /// never deadlock the Synchronize recovery path; persisted in the snapshot
    /// so the bound survives restarts. NOT refreshed on re-sends.
    pub attached_at_unix: Option<u64>,
    /// Monotonic first-derived time (in-memory only, NOT persisted). Combined
    /// with [`attached_at_unix`] the staleness test uses the MAXIMUM of the
    /// two elapsed measurements, so a wall-clock rollback cannot stretch the
    /// proposal's lifetime and a forward jump cannot instantly evict a live
    /// proposal (audit finding #10). None after a snapshot restore — the
    /// persisted wall-clock bound then stands alone.
    #[zeroize(skip)]
    pub attached_at_mono: Option<std::time::Instant>,
}

impl IncomingProposal {
    /// Whether an incoming proposal is pending (a root key or receiving chain
    /// is staged). `is_pending` is the single source of truth used by the
    /// resync path, so a partially-cleared slot can never wedge recovery.
    pub fn is_pending(&self) -> bool {
        self.root_key.is_some() || self.receiving_chain_key.is_some()
    }
}

/// The single OUTGOING rekey proposal slot (our own rekey, awaiting the peer's
/// ACK). Grouped (audit KYP-2026-02 #24) so commit/cancel always clears the
/// whole slot atomically.
#[derive(Clone, Zeroize, ZeroizeOnDrop, Default)]
pub struct OutgoingProposal {
    pub root_key: Option<[u8; 32]>,
    pub sending_chain_key: Option<[u8; 32]>,
    pub receiving_chain_key: Option<[u8; 32]>,
    /// Outgoing hybrid keypair for the next ratchet generation.
    /// Swapped into our_hybrid_pair on commit_outgoing_rekey().
    #[zeroize(skip)]
    pub hybrid_pair: Option<HybridKeyPair>,
    /// Rekey payload of the pending outgoing proposal, retained for re-send.
    #[zeroize(skip)]
    pub rekey_payload: Option<(Vec<u8>, Vec<u8>, Vec<u8>)>,
}

impl OutgoingProposal {
    /// Whether an outgoing proposal is pending (a root key or sending chain is
    /// staged). Single source of truth for the resync/race paths.
    pub fn is_pending(&self) -> bool {
        self.root_key.is_some() || self.sending_chain_key.is_some()
    }
}

/// Replay-protection window: the generation-scoped seen-sequence set plus the
/// frozen highest-delivered watermark of the previous generation (audit
/// KYP-2026-02 #4/#7). Grouped (audit KYP-2026-02 #24) so the delivered
/// watermark and the seen set are reset/reused together.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct ReplayWindow {
    /// Seen (generation, seq) pairs for replay detection. Generation-scoped so
    /// a previous-generation message cannot be mis-identified as a replay of a
    /// current-generation one after the counters reset on a rekey commit.
    #[zeroize(skip)]
    pub seen: std::collections::HashSet<(u32, u64)>,
    /// Highest sequence number DELIVERED on the previous generation before the
    /// rekey commit. Persisted replay watermark: after `seen` is reset by a
    /// commit, this rejects replays of already-delivered previous-generation
    /// messages (audit finding #7).
    pub prev_gen_highest_delivered: Option<u64>,
}

/// Absolute cap on the seen-set size (audit finding #29). The per-generation
/// sliding-window retain in the current-chain path bounds the CURRENT
/// generation, but a sustained burst of previous-generation (out-of-order)
/// deliveries across a rekey commit grows the PREVIOUS-generation tail with no
/// local bound — and every entry is persisted in the snapshot, so unbounded
/// growth is both a memory leak and a snapshot-size leak. The cap is generous
/// (replay detection stays correct for any realistic delivery window) while
/// guaranteeing the set can never grow without bound. (`SEEN_SET_MAX` itself
/// is defined in `policy.rs` and re-exported here.)
impl ReplayWindow {
    /// Insert a seen (generation, seq) pair and enforce the absolute size cap
    /// (audit finding #29): when the set exceeds `SEEN_SET_MAX`, evict the
    /// oldest generation first, then the lowest sequence numbers within the
    /// oldest remaining generation. Replay detection only needs a bounded
    /// window around the current delivery position; the watermark + retained
    /// previous chain cover everything older.
    pub(crate) fn record_delivered(&mut self, gen: u32, seq: u64) {
        self.seen.insert((gen, seq));
        if self.seen.len() <= SEEN_SET_MAX {
            return;
        }
        // Evict oldest generation(s) until back under the cap.
        loop {
            if self.seen.len() <= SEEN_SET_MAX {
                break;
            }
            let oldest_gen = self.seen.iter().map(|(g, _)| *g).min();
            match oldest_gen {
                Some(g) => {
                    let before = self.seen.len();
                    self.seen.retain(|&(cg, _)| cg != g);
                    let removed = before - self.seen.len();
                    if removed == 0 {
                        // Only one generation remains and it is over the cap —
                        // evict the lowest sequences.
                        let mut seqs: Vec<(u32, u64)> = self.seen.iter().copied().collect();
                        seqs.sort();
                        let over = self.seen.len() - SEEN_SET_MAX;
                        for (eg, es) in seqs.into_iter().take(over) {
                            self.seen.remove(&(eg, es));
                        }
                    }
                }
                None => break,
            }
        }
    }
}

/// Post-Quantum Ephemeral Double Ratchet State (Forward Secrecy & Post-Compromise Security)
/// Includes skip-key caching for out-of-order/dropped packet tolerance
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchetState {
    pub root_key: [u8; 32],
    /// Send-space chain: KDF key + position counter of our OUTGOING messages.
    pub send: Chain,
    /// Receive-space chain: KDF key + position counter of INCOMING messages.
    pub recv: Chain,
    pub our_hybrid_pair: HybridKeyPair,
    pub peer_x25519_pk: Option<[u8; 32]>,
    pub peer_mlkem_pk: Option<Vec<u8>>,
    pub rekey_interval: u64,
    pub ratchet_generation: u32,
    /// Pairing epoch (audit finding #2). Incremented whenever this peer's
    /// session is (re)initialized from a fresh KEM handshake. A persisted
    /// snapshot from an OLDER epoch must NEVER be imported over a live session
    /// from a newer epoch — after a re-pair the fresh session (gen 0, new
    /// master secret) would be clobbered by the stale pre-re-pair snapshot
    /// (old key material), a silent state rollback that presents as
    /// "paired but nothing syncs". The import guard in the registry refuses
    /// any import whose epoch differs from the live session's. Persisted in
    /// the snapshot; serde-defaults to 0 for snapshots written before this
    /// field existed.
    pub pairing_epoch: u64,
    /// Receiving-chain key from the previous ratchet generation. Retained after
    /// a rekey commit so messages the peer sent on the previous generation but
    /// that are still in flight (out-of-order delivery) can still be decrypted
    /// (audit finding #3). The anchor and generation scope the retained chain.
    pub previous_recv_chain_key: Option<[u8; 32]>,
    pub previous_recv_anchor: Option<u64>,
    pub previous_recv_gen: Option<u32>,
    /// Replay-protection window: generation-scoped seen-set plus the frozen
    /// highest-delivered watermark of the previous generation (audit #4/#7).
    pub replay_window: ReplayWindow,
    /// ── INCOMING proposal (received rekey payload from the peer). ──
    /// Grouped (audit KYP-2026-02 #24) so the invariant "at most one unconsumed
    /// incoming proposal" is enforced by the type: every field is derived,
    /// committed or cancelled together. Deriving/committing this does NOT touch
    /// our own outgoing proposal. The peer that sends a rekey payload derives
    /// its next sending chain with label "send-chain-from-rekey" and its next
    /// receiving chain with label "recv-chain-from-rekey". As the *receiver*
    /// of that payload we therefore swap the roles: our next receiving chain is
    /// the peer's send chain and our next sending chain is the peer's recv chain.
    pub incoming_proposal: IncomingProposal,
    /// ── OUTGOING proposal (our own rekey, awaiting peer ACK). ──
    /// Grouped (audit KYP-2026-02 #24): set during ratchet_encrypt; committed
    /// by commit_outgoing_rekey() when the peer's RekeyAck (or TTL fallback)
    /// confirms receipt; cancelled atomically by cancel_outgoing_rekey().
    pub outgoing_proposal: OutgoingProposal,
    /// Cached skip keys keyed by (ratchet_generation, seq). Generation-scoped
    /// so keys from the previous generation's receive chain cannot collide with
    /// the current generation's after a rekey commit resets the counters.
    #[zeroize(skip)]
    pub skip_message_keys: Option<SkipKeyMap>,
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
    /// Set when a rekey is committed during decryption. Caller should send a RekeyAck.
    /// Cleared by take_pending_rekey_ack_seq().
    #[zeroize(skip)]
    pub pending_rekey_ack_seq: Option<u64>,
    /// Whether this side initiated the session. Deterministic tie-break for
    /// the two-sided rekey race: the initiator's proposal always wins, so the
    /// responder cancels its own outgoing proposal when the initiator's is
    /// received (see ratchet_decrypt_with_rekey in decrypt.rs).
    pub is_initiator: bool,
    /// Cumulative number of sequence positions advanced by explicit resyncs
    /// (`resync_receiving_chain`) over this session's lifetime. Persisted in the
    /// snapshot and capped by `SYNC_MAX_CUMULATIVE` so a compromised peer cannot
    /// force unbounded forward jumps / KDF work (audit finding #4).
    pub resync_forward_total: u64,
    /// Cache of the last-generated RekeyAck binary TLV, keyed by the carrier
    /// sequence it acknowledges (audit KYP-2026-02 #11). The poll layer uses a
    /// NON-CONSUMING peek so a lost poll response can retry the ack — but each
    /// peek that calls `ratchet_encrypt` advances the SENDER's chain, so N lost
    /// responses previously burned N chain positions (chain burn / skip-cache
    /// pressure / max_skip exhaustion). Re-serving the cached TLV while the
    /// carrier is unchanged makes the peek idempotent. Cleared when the carrier
    /// is consumed or changes. Transient — NOT persisted in the snapshot.
    pub(crate) peeked_ack_cache: Option<(u64, Vec<u8>)>,
}

// ────────────────────────────────────────────────────────────
// Rekey AAD helpers — bind rekey parameters into the AEAD tag
// to prevent attackers from swapping rekey payloads.
// ────────────────────────────────────────────────────────────

/// Build AAD from rekey parameters. Empty when no rekey payload is present.
///
/// Audit KYP-2026-02 #19: a PARTIAL rekey set is an error, not an empty AAD.
/// The sender's AEAD tag was computed over the FULL AAD, so a message carrying
/// a partial set can never authenticate — failing here with a protocol error
/// is honest, where returning an empty AAD produced a misleading
/// "decryption failed" that masked the real (validation) problem.
pub(crate) fn build_rekey_aad(
    rekey_ciphertext: Option<&[u8]>,
    rekey_x25519_pk: Option<&[u8]>,
    rekey_mlkem_pk: Option<&[u8]>,
) -> Result<Vec<u8>, KyberError> {
    let present = rekey_ciphertext.is_some() as u8
        + rekey_x25519_pk.is_some() as u8
        + rekey_mlkem_pk.is_some() as u8;
    if present > 0 && present < 3 {
        return Err(KyberError::CryptoError(
            "Rekey AAD: partial rekey parameter set (must be all-or-nothing)".into(),
        ));
    }
    match (rekey_ciphertext, rekey_x25519_pk, rekey_mlkem_pk) {
        (Some(ct), Some(xpk), Some(mpk)) => {
            let mut aad = Vec::with_capacity(32 + mpk.len() + ct.len() + 3);
            aad.push(b'r');
            aad.extend_from_slice(xpk);
            aad.push(b'm');
            aad.extend_from_slice(mpk);
            aad.push(b'c');
            aad.extend_from_slice(ct);
            Ok(aad)
        }
        _ => Ok(Vec::new()),
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
            send: Chain {
                key: sending_ck,
                message_count: 0,
            },
            recv: Chain {
                key: receiving_ck,
                message_count: 0,
            },
            our_hybrid_pair,
            peer_x25519_pk,
            peer_mlkem_pk,
            rekey_interval: RATCHET_REKEY_INTERVAL,
            ratchet_generation: 0,
            pairing_epoch: 0,
            previous_recv_chain_key: None,
            previous_recv_anchor: None,
            previous_recv_gen: None,
            replay_window: ReplayWindow::default(),
            incoming_proposal: IncomingProposal::default(),
            outgoing_proposal: OutgoingProposal::default(),
            skip_message_keys: Some(HashMap::new()),
            max_skip: 100,
            previous_keypairs: VecDeque::new(),
            max_key_history: 3,
            rekey_pending_confirm_queue: VecDeque::new(),
            pending_rekey_ack_seq: None,
            is_initiator,
            resync_forward_total: 0,
            peeked_ack_cache: None,
        })
    }

    /// Retain the current receiving chain as the PREVIOUS-generation chain so
    /// in-flight messages from the old generation can still be decrypted after
    /// a rekey commit (audit finding #3). Only the immediately-previous chain is
    /// kept: a rekey cannot be ACKed until the previous one is committed, so the
    /// peer can never be more than one generation ahead in our receive space.
    fn retain_previous_receiving_chain(&mut self) {
        self.previous_recv_chain_key = Some(self.recv.key);
        self.previous_recv_anchor = Some(self.recv.message_count);
        self.previous_recv_gen = Some(self.ratchet_generation);
        // Audit finding #7: freeze the highest DELIVERED sequence number before
        // the commit clears `seen_sequence_numbers`. A message whose key was
        // cached before the commit (out-of-order delivery) must not be
        // re-derivable from the retained chain after the reset.
        self.replay_window.prev_gen_highest_delivered = self.capture_previous_recv_watermark();
    }

    /// Highest sequence number delivered on the current generation, used as the
    /// replay watermark for the previous generation after a commit (audit
    /// finding #7). None when nothing has been delivered yet.
    fn capture_previous_recv_watermark(&self) -> Option<u64> {
        let max_seen = self
            .replay_window
            .seen
            .iter()
            .filter(|(gen, _)| *gen == self.ratchet_generation)
            .map(|(_, seq)| *seq)
            .max();
        let contiguous = self.recv.message_count.saturating_sub(1);
        if self.recv.message_count > 0 {
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
        self.send.message_count = 0;
        self.recv.message_count = 0;
        // Audit KYP-2026-02 #4: the OLD generation's CACHED-BUT-UNDELIVERED
        // skip keys MUST survive the commit. A message whose key was derived
        // during a gap skip but not yet received becomes undecryptable after
        // the commit unless the cache retains it — the retained previous chain
        // cannot step backwards below its anchor, so the cache is the ONLY way
        // to deliver it. The cache is keyed by (generation, seq), so old-gen
        // keys can never satisfy a new-generation message, and
        // `prune_skip_keys` retains only the current + previous generations
        // and caps the total size.
        //
        // Seen-seqs remain generation-scoped and are cleared: already-delivered
        // previous-generation messages are re-rejected by the retained chain
        // anchor/watermark (their keys were consumed at delivery, so the cache
        // no longer holds them).
        self.replay_window.seen.clear();
    }

    /// Commit the INCOMING proposal with the SAME race/outgoing bookkeeping the
    /// rekey-aware path applies (audit finding #7). A first new-generation
    /// message authenticating on the pending chain proves the PEER's proposal
    /// is live, so any of our own unacknowledged outgoing proposal lost the
    /// race and MUST be cancelled first — otherwise its stale payload rides
    /// later messages, the peer's initiator branch discards it, and the slot
    /// stays occupied (dead rekey traffic + blocked future rekeys). Routing
    /// every pending-chain commit through this one entry point keeps the two
    /// decrypt paths (plain and rekey-aware) from bit-rotting apart.
    pub(crate) fn commit_pending_rekey_with_race_resolution(&mut self) {
        if self.outgoing_proposal.root_key.is_some() {
            self.cancel_outgoing_rekey();
        }
        self.commit_pending_rekey();
    }

    /// Commit the INCOMING rekey proposal (derived from a rekey payload sent by
    /// the peer). Atomic full transition: root + both chain keys + peer public
    /// keys + generation bump + carrier/ack bookkeeping. Call only after the
    /// pending chain has authenticated a message (AEAD verified).
    pub fn commit_pending_rekey(&mut self) {
        if let (Some(pk), Some(psk), Some(prk)) = (
            self.incoming_proposal.root_key,
            self.incoming_proposal.sending_chain_key,
            self.incoming_proposal.receiving_chain_key,
        ) {
            // Retain the old receiving chain so late previous-generation messages
            // (in flight when this commit happened) still decrypt.
            self.retain_previous_receiving_chain();
            self.root_key = pk;
            self.send.key = psk;
            self.recv.key = prk;
            if let Some(xpk) = self.incoming_proposal.peer_x25519_pk.take() {
                self.peer_x25519_pk = Some(xpk);
            }
            if let Some(mpk) = self.incoming_proposal.peer_mlkem_pk.take() {
                self.peer_mlkem_pk = Some(mpk);
            }
            if self.incoming_proposal.generation_bump {
                self.ratchet_generation = self.ratchet_generation.saturating_add(1);
                self.incoming_proposal.generation_bump = false;
            }
            self.reset_generation_counters();
        }
        // Always clear the pending slot, even on partial/no-op commit.
        self.incoming_proposal.root_key = None;
        self.incoming_proposal.sending_chain_key = None;
        self.incoming_proposal.receiving_chain_key = None;
        self.incoming_proposal.peer_x25519_pk = None;
        self.incoming_proposal.peer_mlkem_pk = None;
        self.incoming_proposal.generation_bump = false;
        self.incoming_proposal.carrier_gen = None;
        self.incoming_proposal.attached_at_unix = None;
        // If we have not yet asked the peer to confirm this proposal, do so now
        // using the recorded carrier sequence (send-space of the rekey message).
        if self.pending_rekey_ack_seq.is_none() {
            self.pending_rekey_ack_seq = self.incoming_proposal.carrier_seq;
        }
        self.incoming_proposal.carrier_seq = None;
    }

    /// Commit the OUTGOING rekey proposal (our own rekey) once the peer has
    /// acknowledged it. Atomic full transition: root + both chain keys + swap
    /// our hybrid keypair + generation bump.
    pub fn commit_outgoing_rekey(&mut self) {
        if let (Some(ok), Some(osk), Some(ork)) = (
            self.outgoing_proposal.root_key,
            self.outgoing_proposal.sending_chain_key,
            self.outgoing_proposal.receiving_chain_key,
        ) {
            // Retain the old receiving chain: the peer may still send messages on
            // the previous generation while it catches up (audit finding #3).
            self.retain_previous_receiving_chain();
            self.root_key = ok;
            self.send.key = osk;
            self.recv.key = ork;
            if let Some(new_pair) = self.outgoing_proposal.hybrid_pair.take() {
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
        self.outgoing_proposal.root_key = None;
        self.outgoing_proposal.sending_chain_key = None;
        self.outgoing_proposal.receiving_chain_key = None;
        self.outgoing_proposal.hybrid_pair = None;
        self.outgoing_proposal.rekey_payload = None;
    }

    /// Cancel an unacknowledged outgoing proposal. Used by the deterministic
    /// two-sided rekey tie-break: when the initiator's proposal preempts the
    /// responder's, the responder cancels its own and adopts the initiator's.
    /// Also used by the Synchronize recovery path to evict an outgoing proposal
    /// that has gone stale (audit KYP-2026-02 #3).
    pub fn cancel_outgoing_rekey(&mut self) {
        self.outgoing_proposal.root_key = None;
        self.outgoing_proposal.sending_chain_key = None;
        self.outgoing_proposal.receiving_chain_key = None;
        self.outgoing_proposal.hybrid_pair = None;
        self.outgoing_proposal.rekey_payload = None;
        self.rekey_pending_confirm_queue.clear();
    }

    /// Cancel an unconsumed INCOMING rekey proposal (audit KYP-2026-02 #3).
    /// Used by the Synchronize recovery path to evict a STALE proposal so the
    /// recovery is never blocked by it. Safe to call when no proposal is
    /// pending. Does not touch our own outgoing proposal.
    pub fn cancel_pending_incoming_rekey(&mut self) {
        self.incoming_proposal.root_key = None;
        self.incoming_proposal.sending_chain_key = None;
        self.incoming_proposal.receiving_chain_key = None;
        self.incoming_proposal.peer_x25519_pk = None;
        self.incoming_proposal.peer_mlkem_pk = None;
        self.incoming_proposal.generation_bump = false;
        self.incoming_proposal.carrier_seq = None;
        self.incoming_proposal.carrier_gen = None;
        self.incoming_proposal.attached_at_unix = None;
    }

    /// Whether the INCOMING proposal has exceeded its bounded lifetime. A
    /// proposal with no recorded attach time is treated as fresh (conservative:
    /// refuses resync until a TTL has demonstrably elapsed).
    ///
    /// Audit finding #10: the lifetime is bounded by BOTH clocks. The elapsed
    /// measurement is the MAXIMUM of the monotonic and wall-clock elapses, so a
    /// wall-clock rollback cannot stretch the proposal's life indefinitely and a
    /// forward jump cannot instantly evict a live proposal.
    pub(crate) fn incoming_proposal_is_stale(&self) -> bool {
        super::policy::incoming_proposal_is_stale(&self.incoming_proposal)
    }

    /// Whether the OUTGOING proposal has exceeded its bounded lifetime. The
    /// proposal's confirm-queue entries carry attach timestamps (the last
    /// re-send). When every entry has outlived the TTL — i.e. the peer has not
    /// acked and no re-send traffic has flowed for the TTL window — the
    /// proposal is stale and must not block recovery.
    ///
    /// Audit finding #8: a restored-but-unacked proposal (queue entries
    /// present, no re-send has flowed since restart) must NOT be evicted. The
    /// monotonic `attached_at` is reset on restore, so staleness here is judged
    /// by the persisted wall-clock `attached_at_unix` (which survives restart)
    /// and the monotonic clock is used only as a floor: the effective age is
    /// the max of both, exactly like the incoming TTL (audit finding #10).
    pub(crate) fn outgoing_proposal_is_stale(&self) -> bool {
        super::policy::outgoing_proposal_is_stale(&self.rekey_pending_confirm_queue)
    }

    /// Record the attach time of a freshly derived INCOMING proposal (audit
    /// KYP-2026-02 #3). Idempotent: keeps the FIRST-seen time so a proposal
    /// that cannot complete within the TTL is eventually evicted even if the
    /// peer keeps re-sending the same (consumable-only-by-new-gen-messages)
    /// proposal on the old chain. Records BOTH the persisted wall-clock and the
    /// in-memory monotonic time (audit finding #10).
    pub(crate) fn stamp_incoming_proposal_attached_at(&mut self) {
        if self.incoming_proposal.attached_at_unix.is_none() {
            self.incoming_proposal.attached_at_unix = Some(now_unix_secs());
        }
        if self.incoming_proposal.attached_at_mono.is_none() {
            self.incoming_proposal.attached_at_mono = Some(std::time::Instant::now());
        }
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
        self.incoming_proposal.carrier_seq = None;
        // The ack was handed to the caller — drop the idempotent-peek cache
        // (audit KYP-2026-02 #11).
        self.peeked_ack_cache = None;
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
