use super::super::{decapsulate_hybrid, decrypt_chacha20, KyberError};
use super::derive::derive_tentative_msg_key;
use super::state::{build_rekey_aad, DoubleRatchetState};
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

/// Single-pass state advancement for pending chain fallback.
/// After AEAD verification on the pending chain, advances recv_message_count
/// and derives skip keys in one pass — eliminates the double-decrypt pattern.
/// Returns (next_chain_key_for_seq+1, skip_keys_map).
///
/// `base_seq` is the chain position the provided chain key is anchored at. For
/// the pending (post-commit) chain this is 0: rekey commits reset the per-
/// generation counters on BOTH sides (audit finding #2), so the first
/// new-generation message is always at chain position 0.
fn advance_receiving_chain(
    recv_chain_key: &[u8; 32],
    base_seq: u64,
    target_seq: u64,
    generation: u32,
    max_skip: usize,
) -> Result<
    (
        [u8; 32],
        std::collections::HashMap<(u32, u64), Zeroizing<[u8; 32]>>,
    ),
    KyberError,
> {
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
fn prune_skip_keys(
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
    /// Decrypt ciphertext with out-of-order tolerance via skip-key caching.
    /// Uses tentative state: only commits chain advancement AFTER AEAD verification succeeds.
    /// If the current chain fails AEAD and a pending rekey chain exists, tries the pending
    /// chain as fallback — this prevents desync when sender commits rekey before receiver
    /// sends any outgoing message.
    /// IMPORTANT: The fallback evaluates AEAD on the pending chain WITHOUT committing state.
    /// Only after AEAD verification succeeds is the state mutation triggered.
    /// The nonce encodes the message sequence number in its first 8 bytes.
    pub fn ratchet_decrypt(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KyberError> {
        self.ratchet_decrypt_with_aad(nonce, ciphertext, &[])
    }

    /// Try to decrypt a message belonging to the PREVIOUS ratchet generation
    /// using the retained previous receiving chain (audit finding #3). Returns
    /// Ok(Some(plaintext)) on success, Ok(None) when this message is not from
    /// the previous generation (or no previous chain is retained).
    fn try_decrypt_previous_generation(
        &mut self,
        nonce_gen: u32,
        seq: u64,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Option<Vec<u8>>, KyberError> {
        let (prev_ck, prev_anchor, prev_gen) = match (
            self.previous_recv_chain_key,
            self.previous_recv_anchor,
            self.previous_recv_gen,
        ) {
            (Some(ck), Some(anchor), Some(gen)) => (ck, anchor, gen),
            _ => return Ok(None),
        };
        if nonce_gen != prev_gen {
            return Ok(None);
        }
        // Replays / already-processed messages must not be re-accepted.
        if self.seen_sequence_numbers.contains(&(prev_gen, seq)) {
            return Err(KyberError::CryptoError(format!(
                "Duplicate sequence number {} detected (replay attack)",
                seq
            )));
        }
        // A message older than the abandoned anchor cannot be positioned on the
        // retained chain — the keys for it were already consumed.
        if seq < prev_anchor {
            return Err(KyberError::SessionDesynchronized(format!(
                "Previous-generation message seq {} predates retained anchor {}",
                seq, prev_anchor
            )));
        }
        // Audit finding #7: the watermark freezes the highest DELIVERED
        // previous-generation sequence number at commit time. A message at or
        // below it was already delivered (possibly via a skip key that the
        // commit then cleared) — accepting it again would be a replay window.
        if let Some(watermark) = self.previous_recv_highest_delivered {
            if seq <= watermark {
                return Err(KyberError::CryptoError(format!(
                    "Previous-generation message seq {} already delivered (watermark {}) — replay",
                    seq, watermark
                )));
            }
        }
        let (next_ck, skip_map) =
            advance_receiving_chain(&prev_ck, prev_anchor, seq, prev_gen, self.max_skip)?;
        // Derive the message key for `seq` from the advanced chain position.
        let mut ck: Zeroizing<[u8; 32]> = Zeroizing::new(prev_ck);
        for _ in prev_anchor..seq {
            let hk = Hkdf::<Sha256>::new(Some(&*ck), b"step");
            let mut next: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
            hk.expand(b"kyberpipe-next-chain", &mut *next)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            ck = next;
        }
        let hk = Hkdf::<Sha256>::new(Some(&*ck), b"step");
        let mut msg_key: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        hk.expand(b"kyberpipe-msg-key", &mut *msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        let plaintext = decrypt_chacha20(&msg_key, nonce, ciphertext, aad)?;
        // AEAD verified — commit the advance on the retained previous chain.
        self.previous_recv_chain_key = Some(next_ck);
        self.previous_recv_anchor = Some(seq + 1);
        self.previous_recv_highest_delivered = Some(
            self.previous_recv_highest_delivered
                .map_or(seq, |w| w.max(seq)),
        );
        let store = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;
        for (k, v) in skip_map {
            store.insert(k, v);
        }
        prune_skip_keys(store, self.ratchet_generation, self.max_skip * 2);
        self.seen_sequence_numbers.insert((prev_gen, seq));
        Ok(Some(plaintext))
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
            if let Some(pt) =
                self.try_decrypt_previous_generation(nonce_gen, seq, nonce, ciphertext, aad)?
            {
                return Ok(pt);
            }
        }

        let skip_keys = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;

        // If this sequence number has a cached key, use it directly
        if let Some(cached_key) = skip_keys.remove(&(nonce_gen, seq)) {
            let plaintext = decrypt_chacha20(&cached_key, nonce, ciphertext, aad)?;
            self.seen_sequence_numbers.insert((nonce_gen, seq));
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
                if let Some(pending_recv_key) = self.pending_receiving_chain_key {
                    if let Ok(pending_msg_key) =
                        derive_tentative_msg_key(&pending_recv_key, 0, seq, self.max_skip)
                    {
                        // Verify AEAD with AAD — capture plaintext in single pass
                        if let Ok(plaintext) =
                            decrypt_chacha20(&pending_msg_key, nonce, ciphertext, aad)
                        {
                            self.commit_pending_rekey();
                            // After the commit the receiving chain is the pending chain
                            // at position 0 with recv_message_count reset to 0.
                            let (next_ck, new_skip) = advance_receiving_chain(
                                &self.receiving_chain_key,
                                0,
                                seq,
                                self.ratchet_generation,
                                self.max_skip,
                            )?;
                            self.receiving_chain_key = next_ck;
                            self.recv_message_count = seq + 1;
                            let store = self.skip_message_keys.as_mut().unwrap();
                            for (k, v) in new_skip {
                                store.insert(k, v);
                            }
                            prune_skip_keys(store, self.ratchet_generation, self.max_skip * 2);
                            self.seen_sequence_numbers
                                .insert((self.ratchet_generation, seq));
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

        if seq > self.recv_message_count {
            let diff = (seq - self.recv_message_count) as usize;
            if diff > self.max_skip {
                return Err(KyberError::SessionDesynchronized(format!(
                    "Sequence gap {} exceeds max_skip {}",
                    diff, self.max_skip
                )));
            }
        }

        let mut tentative_ck: Zeroizing<[u8; 32]> = Zeroizing::new(self.receiving_chain_key);
        let tentative_count = self.recv_message_count;
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
        self.receiving_chain_key = *next_ck;
        self.recv_message_count = seq + 1;
        self.seen_sequence_numbers
            .insert((self.ratchet_generation, seq));
        let lower_bound = self
            .recv_message_count
            .saturating_sub((self.max_skip * 2) as u64);
        self.seen_sequence_numbers
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
    pub fn ratchet_decrypt_with_rekey(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        rekey_ciphertext: Option<&[u8]>,
        rekey_x25519_pk: Option<&[u8; 32]>,
        rekey_mlkem_pk: Option<&[u8]>,
    ) -> Result<Vec<u8>, KyberError> {
        let (nonce_gen, seq) = self.validate_and_extract_nonce(nonce)?;

        // Build AAD from rekey parameters. The AEAD tag will cryptographically
        // bind the rekey payload to this ciphertext — an attacker who strips
        // and replaces the rekey params will cause AEAD verification to fail.
        let aad = build_rekey_aad(
            rekey_ciphertext,
            rekey_x25519_pk.map(|x| x.as_slice()),
            rekey_mlkem_pk,
        );

        // Previous-generation messages (in flight across a rekey commit) are
        // decrypted with the retained previous receiving chain.
        if nonce_gen == self.previous_recv_gen.unwrap_or(u32::MAX)
            && self.previous_recv_chain_key.is_some()
        {
            if let Some(pt) =
                self.try_decrypt_previous_generation(nonce_gen, seq, nonce, ciphertext, &aad)?
            {
                return Ok(pt);
            }
        }

        // A message whose chain position was already derived (e.g. a delayed
        // message that skipped past the current counter during a rekey commit)
        // decrypts directly from the cached skip key. Keyed by generation so a
        // previous-generation key cannot satisfy a current-generation message.
        if let Some(cached_key) = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?
            .remove(&(nonce_gen, seq))
        {
            let plaintext = decrypt_chacha20(&cached_key, nonce, ciphertext, &aad)?;
            self.seen_sequence_numbers.insert((nonce_gen, seq));
            return Ok(plaintext);
        }

        // Phase 1: Tentatively derive the INCOMING proposal from the rekey payload.
        // No active state is mutated here; on AEAD failure everything is rolled back.
        if let (Some(ct), Some(xpk), Some(mpk)) =
            (rekey_ciphertext, rekey_x25519_pk, rekey_mlkem_pk)
        {
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
                if let Ok(decapsulated) = decapsulate_hybrid(ct, &pair.x25519_sk, &pair.mlkem_sk) {
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
            self.pending_root_key = Some(new_root);
            self.pending_sending_chain_key = Some(new_recv);
            self.pending_receiving_chain_key = Some(new_send);
            // Defer peer-key adoption and the generation bump until commit.
            self.pending_peer_x25519_pk = Some(*xpk);
            self.pending_peer_mlkem_pk = Some(mpk.to_vec());
            self.pending_generation_bump = true;
            self.pending_rekey_carrier_seq = Some(seq);
        }

        // Phase 2: Try decryption with the current chain first.
        let result = self.try_decrypt_with_chain(seq, nonce, ciphertext, &aad);

        match result {
            Ok(plaintext) => {
                // AEAD verified on the CURRENT chain. The rekey payload (if
                // any) is bound to this ciphertext, so it is authenticated.
                // Resolve the two-sided rekey race deterministically (audit #5):
                // the INITIATOR's proposal always takes precedence over the
                // responder's, so both peers converge on the same winner.
                let mut adopted_peer_proposal = true;
                if rekey_ciphertext.is_some() && self.outgoing_root_key.is_some() {
                    if self.is_initiator {
                        // Our (initiator's) proposal wins — discard the
                        // responder's tentative proposal and do NOT ACK it.
                        self.pending_root_key = None;
                        self.pending_sending_chain_key = None;
                        self.pending_receiving_chain_key = None;
                        self.pending_peer_x25519_pk = None;
                        self.pending_peer_mlkem_pk = None;
                        self.pending_generation_bump = false;
                        self.pending_rekey_carrier_seq = None;
                        adopted_peer_proposal = false;
                    } else {
                        // Responder: the initiator's proposal preempts ours —
                        // cancel our own outgoing proposal and adopt theirs.
                        self.cancel_outgoing_rekey();
                    }
                }
                if rekey_ciphertext.is_some() && adopted_peer_proposal {
                    // Record/refresh the ACK carrier. If this is a re-sent
                    // proposal, update the ACK to the latest authenticated
                    // carrier so the sender's re-send converges.
                    self.pending_rekey_ack_seq = Some(seq);
                }
                Ok(plaintext)
            }
            Err(first_err) => {
                // Current chain failed. If we have pending keys from the rekey,
                // try the pending chain as fallback.
                if let Some(pending_recv_key) = self.pending_receiving_chain_key {
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
                            // committed its new generation. If we still hold an
                            // unacknowledged outgoing proposal, the initiator-
                            // precedence rule says it lost the race: cancel it so
                            // the two chains converge on the peer's.
                            if self.outgoing_root_key.is_some() {
                                self.cancel_outgoing_rekey();
                            }
                            // AEAD verified on pending chain — atomic full commit.
                            self.commit_pending_rekey();
                            // Advance receiving chain directly — no double-decrypt.
                            // recv_message_count was reset to 0 by the commit, and
                            // the receiving chain key is the pending chain at
                            // position 0.
                            let (next_ck, new_skip) = advance_receiving_chain(
                                &self.receiving_chain_key,
                                0,
                                seq,
                                self.ratchet_generation,
                                self.max_skip,
                            )?;
                            self.receiving_chain_key = next_ck;
                            self.recv_message_count = seq + 1;
                            let store = self.skip_message_keys.as_mut().unwrap();
                            for (k, v) in new_skip {
                                store.insert(k, v);
                            }
                            prune_skip_keys(store, self.ratchet_generation, self.max_skip * 2);
                            self.seen_sequence_numbers
                                .insert((self.ratchet_generation, seq));
                            return Ok(plaintext);
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

        if self.seen_sequence_numbers.contains(&(nonce_gen, seq)) {
            return Err(KyberError::CryptoError(format!(
                "Duplicate sequence number {} detected (replay attack)",
                seq
            )));
        }

        Ok((nonce_gen, seq))
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
        // Refuse to resync while any rekey proposal is unconsumed — jumping the
        // chain across a generation boundary would derive garbage keys.
        if self.pending_root_key.is_some()
            || self.pending_receiving_chain_key.is_some()
            || self.outgoing_root_key.is_some()
            || self.outgoing_sending_chain_key.is_some()
        {
            return Err(KyberError::CryptoError(
                "Synchronize refused: an unconsumed rekey proposal is pending — resolve it first"
                    .into(),
            ));
        }
        let cur = self.recv_message_count;
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
        let mut ck: Zeroizing<[u8; 32]> = Zeroizing::new(self.receiving_chain_key);
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
        self.receiving_chain_key = *ck;
        self.recv_message_count = target_seq;
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
