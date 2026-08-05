use super::super::{decapsulate_hybrid, decrypt_chacha20, KyberError};
use super::derive::derive_tentative_msg_key;
use super::resync::{
    advance_receiving_chain, prune_skip_keys, try_decrypt_with_cached_key, SkipKeyMap,
};
use super::state::{build_rekey_aad, DoubleRatchetState};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::HashMap;
use zeroize::Zeroizing;

/// Explicit receive-path decision outcome (audit KYP-2026-02 #22/#24). The
/// decrypt path is modeled as a small state machine — previous-generation →
/// cached-key → current-chain → pending-chain → resync-request — and every
/// successful message classifies into exactly one outcome, making the decision
/// table explicit instead of implicit in nested `if let` branches. `Replay` and
/// `GapExceeded` are the two failure classifications the machine must surface
/// distinctly (a replay is never a delivery; a gap beyond `max_skip` is never
/// a no-op).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptOutcome {
    /// Decrypted on the active (or retained previous) chain; state advanced.
    Committed,
    /// Decrypted from the skip-key cache (gap-skip delivery); active chain
    /// position did not advance.
    Skipped,
    /// The message carried a rekey payload whose incoming proposal was derived
    /// (a rekey carrier, in-order or out-of-order).
    ProposalDerived,
    /// Rejected as a duplicate / replay.
    Replay,
    /// Rejected because the sequence gap exceeds `max_skip`.
    GapExceeded,
}

impl DoubleRatchetState {
    /// Decrypt ciphertext with out-of-order tolerance via skip-key caching.
    /// Uses tentative state: only commits chain advancement AFTER AEAD verification succeeds.
    /// If the current chain fails AEAD and a pending rekey chain exists, tries the pending
    /// chain as fallback — this prevents desync when sender commits rekey before receiver
    /// sends any outgoing message.
    /// IMPORTANT: The fallback evaluates AEAD on the pending chain WITHOUT committing state.
    /// Only after AEAD verification succeeds is the state mutation triggered.
    /// The nonce encodes the message sequence number in its first 8 bytes.
    ///
    /// AUDIT F4: this is the NON-rekey-aware path. It must ONLY be handed
    /// messages verified to carry NO rekey fields — a rekey carrier is
    /// AEAD-bound to its rekey parameters (empty AAD here cannot
    /// authenticate), so decrypting one here silently drops the peer's
    /// proposal (no Phase-1 derivation, no race resolution, no ACK
    /// bookkeeping). The registry entry point
    /// [`ratchet_ffi::ratchet_decrypt_message_impl`] enforces this with a
    /// distinct `CarrierMisrouted` error; crate-internal callers with a full
    /// message must use `ratchet_decrypt_with_rekey` when rekey fields are
    /// present (the UniFFI binary dispatcher and the sync/ack consumers all
    /// do).
    pub fn ratchet_decrypt(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KyberError> {
        self.ratchet_decrypt_with_aad(nonce, ciphertext, &[])
    }

    /// Decrypt with out-of-order tolerance and optional AAD for rekey binding.
    fn ratchet_decrypt_with_aad(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, KyberError> {
        let (nonce_gen, seq) = self.validate_and_extract_nonce(nonce)?;

        // Previous-generation messages (in flight across a rekey commit) are
        // decrypted with the retained previous receiving chain.
        if nonce_gen == self.previous_recv_gen.unwrap_or(u32::MAX)
            && self.previous_recv_chain_key.is_some()
        {
            if let Some((pt, _from_cache)) =
                self.try_decrypt_previous_generation(nonce_gen, seq, nonce, ciphertext, aad)?
            {
                return Ok(pt);
            }
        }

        let skip_keys = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;

        // If this sequence number has a cached key, use it directly. Shared
        // verify-then-remove helper (AUDIT FINDING #13 + AUDIT #5): the key is
        // consumed ONLY after AEAD verifies — a bit-flipped copy of a
        // legitimate out-of-order message must not permanently consume it.
        if let Some(plaintext) =
            try_decrypt_with_cached_key(skip_keys, nonce_gen, seq, nonce, ciphertext, aad)?
        {
            self.replay_window.record_delivered(nonce_gen, seq);
            return Ok(plaintext);
        }

        // Attempt decryption with current chain.
        let result = self.try_decrypt_with_chain(seq, nonce, ciphertext, aad);

        match result {
            Ok(plaintext) => Ok(plaintext),
            Err(first_err) => {
                // If pending keys exist, verify AEAD on pending chain BEFORE committing.
                // The pending chain is anchored at position 0 (rekey commits reset the
                // per-generation counters on both sides — audit finding #2), so the
                // derivation never walks the mutable recv_message_count.
                if let Some(pending_recv_key) = self.incoming_proposal.receiving_chain_key {
                    if let Ok(pending_msg_key) =
                        derive_tentative_msg_key(&pending_recv_key, 0, seq, self.max_skip)
                    {
                        // Verify AEAD with AAD — capture plaintext in single pass
                        if let Ok(plaintext) =
                            decrypt_chacha20(&pending_msg_key, nonce, ciphertext, aad)
                        {
                            // AUDIT #7: this non-rekey path must apply the SAME
                            // race/outgoing bookkeeping as the rekey-aware path
                            // — committing the peer's proposal while our own
                            // stale outgoing proposal stays live leaves dead
                            // rekey traffic on the wire and occupies the slot.
                            self.commit_pending_rekey_with_race_resolution();
                            // After the commit the receiving chain is the pending chain
                            // at position 0 with recv_message_count reset to 0.
                            let (next_ck, new_skip) = advance_receiving_chain(
                                &self.recv.key,
                                0,
                                seq,
                                self.ratchet_generation,
                                self.max_skip,
                            )?;
                            self.recv.key = next_ck;
                            self.recv.message_count = seq + 1;
                            let store = self.skip_message_keys.as_mut().unwrap();
                            for (k, v) in new_skip {
                                store.insert(k, v);
                            }
                            prune_skip_keys(store, self.ratchet_generation, self.max_skip * 2);
                            self.replay_window
                                .record_delivered(self.ratchet_generation, seq);
                            return Ok(plaintext);
                        }
                    }
                    // Transient AEAD failure on the pending chain MUST NOT roll the
                    // proposal back (audit finding #2): the pending proposal stays
                    // until either it authenticates or the session is explicitly
                    // resynced. Rolling it back on a single out-of-order arrival
                    // converts a transient reordering into permanent desync.
                }
                Err(first_err)
            }
        }
    }

    /// Internal: attempt decryption with current chain.
    /// Derives keys tentatively and only commits on success.
    fn try_decrypt_with_chain(
        &mut self,
        seq: u64,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, KyberError> {
        let skip_keys = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;

        if seq > self.recv.message_count {
            let diff = (seq - self.recv.message_count) as usize;
            if diff > self.max_skip {
                return Err(KyberError::SessionDesynchronized(format!(
                    "Sequence gap {} exceeds max_skip {}",
                    diff, self.max_skip
                )));
            }
        }

        let mut tentative_ck: Zeroizing<[u8; 32]> = Zeroizing::new(self.recv.key);
        let tentative_count = self.recv.message_count;
        let mut tentative_skip: SkipKeyMap = HashMap::new();

        for skip_seq in tentative_count..seq {
            let hk = Hkdf::<Sha256>::new(Some(&*tentative_ck), b"step");
            let mut skip_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
            hk.expand(b"kyberpipe-msg-key", &mut *skip_key)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            hk.expand(b"kyberpipe-next-chain", &mut *tentative_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            tentative_skip.insert((self.ratchet_generation, skip_seq), skip_key);
        }

        let hk = Hkdf::<Sha256>::new(Some(&*tentative_ck), b"step");
        let mut target_msg_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        hk.expand(b"kyberpipe-msg-key", &mut *target_msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        let mut next_ck: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        hk.expand(b"kyberpipe-next-chain", &mut *next_ck)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        let plaintext = decrypt_chacha20(&target_msg_key, nonce, ciphertext, aad)?;

        // AEAD verified — COMMIT state
        self.recv.key = *next_ck;
        self.recv.message_count = seq + 1;
        self.replay_window
            .record_delivered(self.ratchet_generation, seq);
        let lower_bound = self
            .recv
            .message_count
            .saturating_sub((self.max_skip * 2) as u64);
        self.replay_window
            .seen
            .retain(|&(gen, s)| gen == self.ratchet_generation && s >= lower_bound);
        // NOTE: no cross-space rekey queue mutation here. The confirm queue holds
        // OUR OWN send-space carrier seqs; this receive-space seq is on a different
        // chain. Confirmations happen only via the explicit RekeyAck protocol.
        for (k, v) in tentative_skip {
            skip_keys.insert(k, v);
        }
        prune_skip_keys(skip_keys, self.ratchet_generation, self.max_skip * 2);

        Ok(plaintext)
    }

    /// Decrypt a message that may include an incoming DH re-key payload.
    /// If a rekey payload is present, tentatively derives the INCOMING proposal
    /// (with send/recv roles swapped, since the payload was produced by the peer)
    /// WITHOUT mutating active state. The proposal is committed atomically by
    /// commit_pending_rekey() only once a message authenticates under the pending
    /// chain. Peer keys, generation and chain switching all happen at that commit.
    /// The RekeyAck carrier (this message's receive-space seq) is recorded so the
    /// poll layer can confirm the rekey back to the sender in the sender's space.
    /// Classified variant of [`ratchet_decrypt_with_rekey`]: returns the
    /// plaintext plus the explicit [`DecryptOutcome`] decision classification
    /// (audit KYP-2026-02 #22) so callers can observe exactly which branch of
    /// the receive state machine handled the message.
    pub fn ratchet_decrypt_with_rekey_classified(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        rekey_ciphertext: Option<&[u8]>,
        rekey_x25519_pk: Option<&[u8; 32]>,
        rekey_mlkem_pk: Option<&[u8]>,
    ) -> Result<(Vec<u8>, DecryptOutcome), KyberError> {
        let (nonce_gen, seq) = self.validate_and_extract_nonce(nonce)?;

        // Build AAD from rekey parameters. The AEAD tag will cryptographically
        // bind the rekey payload to this ciphertext — an attacker who strips
        // and replaces the rekey params will cause AEAD verification to fail.
        // A partial set is a protocol error, never an empty AAD (audit
        // KYP-2026-02 #19).
        let aad = build_rekey_aad(
            rekey_ciphertext,
            rekey_x25519_pk.map(|x| x.as_slice()),
            rekey_mlkem_pk,
        )?;

        // Previous-generation messages (in flight across a rekey commit) are
        // decrypted with the retained previous receiving chain.
        if nonce_gen == self.previous_recv_gen.unwrap_or(u32::MAX)
            && self.previous_recv_chain_key.is_some()
        {
            if let Some((pt, from_cache)) =
                self.try_decrypt_previous_generation(nonce_gen, seq, nonce, ciphertext, &aad)?
            {
                let outcome = if from_cache {
                    DecryptOutcome::Skipped
                } else {
                    DecryptOutcome::Committed
                };
                return Ok((pt, outcome));
            }
        }

        // Phase 1: Tentatively derive the INCOMING proposal from the rekey
        // payload. This MUST run before the cached-key dispatch below (audit
        // KYP-2026-02 #1): a rekey carrier whose key was derived during a gap
        // skip (out-of-order delivery — e.g. seq 102 arrived before the carrier
        // at seq 100, so the carrier's key is in the skip cache) decrypts from
        // the cache. If the proposal were derived only AFTER the cached-key
        // branch, the payload's cryptographic meaning — a new-generation
        // proposal — would be discarded, no ACK would be queued, and the
        // session would silently desync at the generation boundary. Derivation
        // is idempotent and only sets pending_* fields (no active state is
        // mutated); a stale re-send simply re-derives the same proposal and
        // refreshes the ACK carrier.
        //
        // Note: on AEAD failure the pending_* fields intentionally remain set
        // (audit finding #2) — a transient out-of-order arrival must not roll
        // the proposal back. Staleness/eviction is handled separately by the
        // Synchronize recovery path (audit KYP-2026-02 #3).
        //
        // AUDIT F1: the slot is guarded against STALE carriers before anything
        // is staged. The derivation uses `self.root_key` AT DERIVATION TIME;
        // after this side commits its own proposal (its root advanced), a
        // crossed/re-sent peer carrier from an older generation still
        // decapsulates through the retained previous keypairs, but deriving it
        // under the NEW root produces a garbage proposal (the peer derived its
        // chains under its own old root) that then blocks the single
        // incoming-proposal slot for up to INCOMING_REKEY_TTL_SECS. Two
        // independent guards keep a stale carrier from ever touching the slot:
        //   1. A carrier whose generation is OLDER than our current
        //      ratchet_generation is superseded — its proposal, even if it
        //      decapsulates, cannot be the peer's live next generation.
        //   2. A carrier older than the generation of an ALREADY-PENDING
        //      proposal must not overwrite the newer proposal with an older
        //      re-send (an in-order re-send at the same generation re-derives
        //      the identical proposal, which is safe).
        if let (Some(ct), Some(xpk), Some(mpk)) =
            (rekey_ciphertext, rekey_x25519_pk, rekey_mlkem_pk)
        {
            let superseded = nonce_gen < self.ratchet_generation;
            let older_than_pending = self
                .incoming_proposal
                .carrier_gen
                .is_some_and(|g| nonce_gen < g);
            if superseded || older_than_pending {
                tracing::warn!(
                    "[Decrypt] Dropping rekey carrier from superseded generation {nonce_gen} (current {}) — slot untouched",
                    self.ratchet_generation
                );
            } else {
                // Decapsulate with our CURRENT keypair first (the normal case), then
                // fall back to the retained previous keypairs: the peer may have
                // encapsulated to our previous public keys before learning of our
                // commit (audit finding #3 — the history is no longer dead code).
                // Audit finding #18: the decapsulated shared secret is secret
                // material — keep it in a Zeroizing buffer so error paths cannot
                // leave it in freed heap memory.
                let mut ss: Option<Zeroizing<Vec<u8>>> = None;
                let mut ss_source: Option<usize> = None;
                for (idx, pair) in std::iter::once(&self.our_hybrid_pair)
                    .chain(self.previous_keypairs.iter())
                    .enumerate()
                {
                    if let Ok(decapsulated) =
                        decapsulate_hybrid(ct, &pair.x25519_sk, &pair.mlkem_sk)
                    {
                        ss = Some(Zeroizing::new(decapsulated));
                        ss_source = Some(idx);
                        break;
                    }
                }
                let ss = ss.ok_or_else(|| {
                    KyberError::DecapsulationFailed(
                        "Rekey ciphertext cannot be decapsulated with current or retained keypairs"
                            .into(),
                    )
                })?;
                let _ = ss_source;
                // AUDIT F2 FIX: a NEWER-generation carrier that REPLACES an
                // older pending proposal must not inherit the old proposal's
                // age. `stamp_incoming_proposal_attached_at` is idempotent
                // (first-seen wins) — the legacy code kept the older
                // proposal's `attached_at_unix`, so a proposal staged at
                // T-59s that gets superseded was instantly "stale" under the
                // 60s TTL and evicted by the Synchronize recovery path
                // prematurely. Only identical-generation re-sends (which
                // re-derive the identical proposal) keep the first-seen stamp,
                // so a proposal the peer never completes still ages out.
                if self
                    .incoming_proposal
                    .carrier_gen
                    .is_some_and(|g| g < nonce_gen)
                {
                    self.incoming_proposal.attached_at_unix = None;
                    self.incoming_proposal.attached_at_mono = None;
                }
                let hk2 = Hkdf::<Sha256>::new(Some(&self.root_key), &ss);
                let mut new_root = [0u8; 32];
                let mut new_send = [0u8; 32];
                let mut new_recv = [0u8; 32];
                hk2.expand(b"kyberpipe-next-root-key", &mut new_root)
                    .map_err(|e| KyberError::CryptoError(e.to_string()))?;
                hk2.expand(b"kyberpipe-next-send-chain-from-rekey", &mut new_send)
                    .map_err(|e| KyberError::CryptoError(e.to_string()))?;
                hk2.expand(b"kyberpipe-next-recv-chain-from-rekey", &mut new_recv)
                    .map_err(|e| KyberError::CryptoError(e.to_string()))?;
                // The peer (rekey sender) will send on new_send and receive on new_recv.
                // As the receiver we swap: our receiving chain is the peer's send chain
                // and our sending chain is the peer's recv chain.
                self.incoming_proposal.root_key = Some(new_root);
                self.incoming_proposal.sending_chain_key = Some(new_recv);
                self.incoming_proposal.receiving_chain_key = Some(new_send);
                // Defer peer-key adoption and the generation bump until commit.
                self.incoming_proposal.peer_x25519_pk = Some(*xpk);
                self.incoming_proposal.peer_mlkem_pk = Some(mpk.to_vec());
                self.incoming_proposal.generation_bump = true;
                self.incoming_proposal.carrier_seq = Some(seq);
                self.incoming_proposal.carrier_gen = Some(nonce_gen);
                // Bound the proposal's lifetime so the Synchronize recovery path is
                // never deadlocked by an unconsumed proposal (audit KYP-2026-02 #3).
                self.stamp_incoming_proposal_attached_at();
            }
        }

        // Cached-key dispatch: a message whose chain position was already
        // derived (e.g. a delayed message that skipped past the current counter
        // during a rekey commit) decrypts directly from the cached skip key.
        // Keyed by generation so a previous-generation key cannot satisfy a
        // current-generation message. Runs AFTER Phase 1 so an out-of-order
        // rekey carrier is never silently stripped of its proposal (audit
        // KYP-2026-02 #1).
        //
        // AUDIT FINDING #13 (verify-then-remove): the cached key is consumed
        // ONLY after AEAD verifies — a bit-flipped copy of a legitimate
        // out-of-order message must not permanently consume the key and DoS
        // the real message when it arrives.
        let skip_keys = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;
        // Shared verify-then-remove helper (AUDIT FINDING #13 + AUDIT #5) — the
        // key is consumed only after AEAD verifies.
        if let Some(plaintext) =
            try_decrypt_with_cached_key(skip_keys, nonce_gen, seq, nonce, ciphertext, &aad)?
        {
            self.replay_window.record_delivered(nonce_gen, seq);
            // Resolve the two-sided rekey race + ACK bookkeeping exactly like
            // the current-chain success path — an out-of-order carrier must be
            // acknowledged identically to an in-order one.
            self.resolve_rekey_race_and_ack(seq, rekey_ciphertext.is_some());
            let outcome = if rekey_ciphertext.is_some() {
                DecryptOutcome::ProposalDerived
            } else {
                DecryptOutcome::Skipped
            };
            return Ok((plaintext, outcome));
        }

        // Phase 2: Try decryption with the current chain first.
        let result = self.try_decrypt_with_chain(seq, nonce, ciphertext, &aad);

        match result {
            Ok(plaintext) => {
                // AEAD verified on the CURRENT chain. The rekey payload (if
                // any) is bound to this ciphertext, so it is authenticated.
                // Resolve the two-sided rekey race deterministically (audit #5)
                // and record/refresh the ACK carrier — shared with the
                // cached-key dispatch so an out-of-order carrier gets identical
                // bookkeeping (audit KYP-2026-02 #1).
                self.resolve_rekey_race_and_ack(seq, rekey_ciphertext.is_some());
                let outcome = if rekey_ciphertext.is_some() {
                    DecryptOutcome::ProposalDerived
                } else {
                    DecryptOutcome::Committed
                };
                Ok((plaintext, outcome))
            }
            Err(first_err) => {
                // Current chain failed. If we have pending keys from the rekey,
                // try the pending chain as fallback.
                if let Some(pending_recv_key) = self.incoming_proposal.receiving_chain_key {
                    // The pending chain is anchored at position 0 — rekey commits
                    // reset per-generation counters on both sides (audit finding
                    // #2), so derive_tentative_msg_key never walks the mutable
                    // recv_message_count of the (possibly drifted) old generation.
                    if let Ok(pending_msg_key) =
                        derive_tentative_msg_key(&pending_recv_key, 0, seq, self.max_skip)
                    {
                        // Single-pass: verify AEAD AND capture plaintext in one call
                        if let Ok(plaintext) =
                            decrypt_chacha20(&pending_msg_key, nonce, ciphertext, &aad)
                        {
                            // AEAD verified on pending chain — the peer has already
                            // committed its new generation. Route the commit through
                            // the shared race-resolution entry (audit #7) so our own
                            // unacknowledged outgoing proposal is cancelled exactly
                            // like the plain decrypt path does — the two pending
                            // commit paths can never diverge again.
                            self.commit_pending_rekey_with_race_resolution();
                            // Advance receiving chain directly — no double-decrypt.
                            // recv_message_count was reset to 0 by the commit, and
                            // the receiving chain key is the pending chain at
                            // position 0.
                            let (next_ck, new_skip) = advance_receiving_chain(
                                &self.recv.key,
                                0,
                                seq,
                                self.ratchet_generation,
                                self.max_skip,
                            )?;
                            self.recv.key = next_ck;
                            self.recv.message_count = seq + 1;
                            let store = self.skip_message_keys.as_mut().unwrap();
                            for (k, v) in new_skip {
                                store.insert(k, v);
                            }
                            prune_skip_keys(store, self.ratchet_generation, self.max_skip * 2);
                            self.replay_window
                                .record_delivered(self.ratchet_generation, seq);
                            return Ok((plaintext, DecryptOutcome::Committed));
                        }
                    }
                    // Transient AEAD failure on the pending chain MUST NOT roll the
                    // proposal back (audit finding #2): an out-of-order first
                    // new-generation message must not destroy the pending proposal.
                }
                Err(first_err)
            }
        }
    }

    /// Decrypt a message that may include an incoming DH re-key payload.
    /// Convenience wrapper over [`Self::ratchet_decrypt_with_rekey_classified`]
    /// returning just the plaintext (the explicit [`DecryptOutcome`]
    /// classification is available via the classified variant).
    pub fn ratchet_decrypt_with_rekey(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        rekey_ciphertext: Option<&[u8]>,
        rekey_x25519_pk: Option<&[u8; 32]>,
        rekey_mlkem_pk: Option<&[u8]>,
    ) -> Result<Vec<u8>, KyberError> {
        self.ratchet_decrypt_with_rekey_classified(
            nonce,
            ciphertext,
            rekey_ciphertext,
            rekey_x25519_pk,
            rekey_mlkem_pk,
        )
        .map(|(pt, _outcome)| pt)
    }

    /// Resolve the two-sided rekey race deterministically (audit #5) and
    /// record/refresh the RekeyAck carrier. Shared by the current-chain success
    /// path AND the cached-key dispatch so an out-of-order rekey carrier gets
    /// exactly the same bookkeeping as an in-order one (audit KYP-2026-02 #1).
    /// `has_rekey_payload` is whether the authenticated message carried a rekey
    /// payload; `seq` is its receive-space sequence number.
    ///
    /// AUDIT FINDING #3 (payload-anchored tie-break): the winner of a
    /// simultaneous two-sided rekey is the proposal whose rekey x25519 public
    /// key is lexicographically larger. Both sides hold BOTH proposals at race
    /// time — our own staged `outgoing_proposal.rekey_payload` plus the peer's
    /// carrier payload (`rekey_x25519_pk`/`rekey_mlkem_pk`, cryptographically
    /// bound into the message's rekey AAD) — so both evaluate the SAME pair and
    /// deterministically agree. The legacy parity heuristic
    /// (`ratchet_generation % 2 == 0`) required both sides to observe the same
    /// current generation; a transient generation drift (exactly the condition
    /// the Synchronize path repairs) flipped the parity for one side, both
    /// picked the same "winner", and the loser's proposal was cancelled on one
    /// side but staged-but-unacked on the other — dead rekey traffic until TTL
    /// eviction. The nonce/public-key anchored comparison needs NO shared
    /// generation state, so drift can no longer make the two sides disagree.
    fn resolve_rekey_race_and_ack(&mut self, seq: u64, has_rekey_payload: bool) {
        if !has_rekey_payload {
            return;
        }
        if self.outgoing_proposal.root_key.is_some() {
            // Compare (x25519 pk, mlkem pk) tuples lexicographically. Both are
            // bound into the rekey payload's AEAD AAD, so neither side can be
            // fed a forged comparison input by an on-path attacker.
            let peer_wins = match (
                self.outgoing_proposal.rekey_payload.as_ref(),
                self.incoming_proposal.peer_x25519_pk,
                self.incoming_proposal.peer_mlkem_pk.as_deref(),
            ) {
                (Some((our_xpk, our_mpk, _)), Some(peer_xpk), Some(peer_mpk)) => {
                    (peer_xpk.as_slice(), peer_mpk) > (our_xpk.as_slice(), our_mpk.as_slice())
                }
                // We staged an outgoing proposal but the peer's carrier did not
                // stage an incoming one (e.g. superseded generation) — nothing
                // to race against; we win by default and do not ACK.
                (Some(_), _, _) => false,
                (None, _, _) => true,
            };
            if peer_wins {
                // We lost the race — cancel our own outgoing proposal and
                // adopt the peer's (already staged in Phase 1), then ACK it.
                self.cancel_outgoing_rekey();
            } else {
                // Our proposal wins — discard the peer's tentative proposal and
                // do NOT ACK it (the peer cancels its own when it sees ours).
                self.cancel_pending_incoming_rekey();
                return;
            }
        }
        // Record/refresh the ACK carrier. If this is a re-sent proposal, update
        // the ACK to the latest authenticated carrier so the sender's re-send
        // converges.
        self.pending_rekey_ack_seq = Some(seq);
    }

    fn validate_and_extract_nonce(&self, nonce: &[u8; 12]) -> Result<(u32, u64), KyberError> {
        let nonce_gen = u32::from_be_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        let seq = u64::from_be_bytes([
            nonce[4], nonce[5], nonce[6], nonce[7], nonce[8], nonce[9], nonce[10], nonce[11],
        ]);

        if self.ratchet_generation == u32::MAX {
            return Err(KyberError::CryptoError(
                "Ratchet generation at u32::MAX — nonce reuse risk. Re-pair required.".into(),
            ));
        }
        // Accept the current generation, the next generation (a rekey payload or
        // first new-generation message), and the PREVIOUS generation while a
        // previous receiving chain is retained (in-flight messages across a
        // rekey commit — audit finding #3). Messages two+ generations away are
        // rejected: the peer cannot be more than one generation ahead in our
        // receive space because a rekey must be ACKed before the next commits.
        let expected_prev = self.previous_recv_gen.unwrap_or(u32::MAX);
        let ok = nonce_gen == self.ratchet_generation
            || nonce_gen == self.ratchet_generation.saturating_add(1)
            || (nonce_gen == expected_prev && self.previous_recv_chain_key.is_some());
        if !ok {
            return Err(KyberError::CryptoError(format!(
                "Nonce generation mismatch: expected {} or {}, got {}",
                self.ratchet_generation,
                self.ratchet_generation.saturating_add(1),
                nonce_gen
            )));
        }

        if self.replay_window.seen.contains(&(nonce_gen, seq)) {
            return Err(KyberError::CryptoError(format!(
                "Duplicate sequence number {} detected (replay attack)",
                seq
            )));
        }

        Ok((nonce_gen, seq))
    }
}
