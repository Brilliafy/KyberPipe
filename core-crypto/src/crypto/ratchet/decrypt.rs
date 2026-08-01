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

/// Single-pass state advancement for pending chain fallback.
/// After AEAD verification on the pending chain, advances recv_message_count
/// and derives skip keys in one pass — eliminates the double-decrypt pattern.
/// Returns (next_chain_key_for_seq+1, skip_keys_map).
fn advance_receiving_chain(
    recv_chain_key: &[u8; 32],
    recv_message_count: u64,
    target_seq: u64,
    max_skip: usize,
) -> Result<([u8; 32], std::collections::HashMap<u64, [u8; 32]>), KyberError> {
    if target_seq > recv_message_count {
        let diff = (target_seq - recv_message_count) as usize;
        if diff > max_skip {
            return Err(KyberError::SessionDesynchronized(format!(
                "Sequence gap {} exceeds max_skip {}",
                diff, max_skip
            )));
        }
    }
    let mut ck = *recv_chain_key;
    let mut skip_keys = std::collections::HashMap::new();
    for skip_seq in recv_message_count..target_seq {
        let hk = Hkdf::<Sha256>::new(Some(&ck), b"step");
        let mut skip_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut skip_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-chain", &mut ck)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        skip_keys.insert(skip_seq, skip_key);
    }
    let hk = Hkdf::<Sha256>::new(Some(&ck), b"step");
    let mut next_ck = [0u8; 32];
    hk.expand(b"kyberpipe-next-chain", &mut next_ck)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
    Ok((next_ck, skip_keys))
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

    /// Decrypt with out-of-order tolerance and optional AAD for rekey binding.
    fn ratchet_decrypt_with_aad(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, KyberError> {
        let (_nonce_gen, seq) = self.validate_and_extract_nonce(nonce)?;

        let skip_keys = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;

        // If this sequence number has a cached key, use it directly
        if let Some(cached_key) = skip_keys.remove(&seq) {
            let plaintext = decrypt_chacha20(&cached_key, nonce, ciphertext, aad)?;
            self.seen_sequence_numbers.insert(seq);
            return Ok(plaintext);
        }

        // Attempt decryption with current chain.
        let result = self.try_decrypt_with_chain(seq, nonce, ciphertext, aad);

        match result {
            Ok(plaintext) => Ok(plaintext),
            Err(first_err) => {
                // If pending keys exist, verify AEAD on pending chain BEFORE committing
                if let Some(pending_recv_key) = self.pending_receiving_chain_key {
                    // Derive msg key from pending chain (non-mutating, sandboxed)
                    if let Ok(pending_msg_key) = derive_tentative_msg_key(
                        &pending_recv_key,
                        self.recv_message_count,
                        seq,
                        self.max_skip,
                    ) {
                        // Verify AEAD with AAD — capture plaintext in single pass
                        if let Ok(plaintext) = decrypt_chacha20(&pending_msg_key, nonce, ciphertext, aad) {
                            self.commit_pending_rekey();
                            // Advance state directly — no double-decrypt
                            let (next_ck, new_skip) = advance_receiving_chain(
                                &self.receiving_chain_key,
                                self.recv_message_count,
                                seq,
                                self.max_skip,
                            )?;
                            self.receiving_chain_key = next_ck;
                            self.recv_message_count = seq + 1;
                            let store = self.skip_message_keys.as_mut().unwrap();
                            for (k, v) in new_skip {
                                store.insert(k, zeroize::Zeroizing::new(v));
                            }
                            while store.len() > self.max_skip {
                                let oldest = *store.keys().min().unwrap_or(&0);
                                store.remove(&oldest);
                            }
                            self.seen_sequence_numbers.insert(seq);
                            let lower_bound = self.recv_message_count.saturating_sub((self.max_skip * 2) as u64);
                            self.seen_sequence_numbers.retain(|&s| s >= lower_bound);
                            return Ok(plaintext);
                        }
                    }
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

        let mut tentative_ck = self.receiving_chain_key;
        let tentative_count = self.recv_message_count;
        let mut tentative_skip: HashMap<u64, [u8; 32]> = HashMap::new();

        for skip_seq in tentative_count..seq {
            let hk = Hkdf::<Sha256>::new(Some(&tentative_ck), b"step");
            let mut skip_key = [0u8; 32];
            hk.expand(b"kyberpipe-msg-key", &mut skip_key)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            hk.expand(b"kyberpipe-next-chain", &mut tentative_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            tentative_skip.insert(skip_seq, skip_key);
        }

        let hk = Hkdf::<Sha256>::new(Some(&tentative_ck), b"step");
        let mut target_msg_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut target_msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        let mut next_ck = [0u8; 32];
        hk.expand(b"kyberpipe-next-chain", &mut next_ck)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        let plaintext = decrypt_chacha20(&target_msg_key, nonce, ciphertext, aad)?;

        // AEAD verified — COMMIT state
        self.receiving_chain_key = next_ck;
        self.recv_message_count = seq + 1;
        self.seen_sequence_numbers.insert(seq);
        let lower_bound = self.recv_message_count.saturating_sub((self.max_skip * 2) as u64);
        self.seen_sequence_numbers.retain(|&s| s >= lower_bound);
        // NOTE: no cross-space rekey queue mutation here. The confirm queue holds
        // OUR OWN send-space carrier seqs; this receive-space seq is on a different
        // chain. Confirmations happen only via the explicit RekeyAck protocol.
        for (k, v) in tentative_skip {
            skip_keys.insert(k, Zeroizing::new(v));
        }
        while skip_keys.len() > self.max_skip {
            let oldest = *skip_keys.keys().min().unwrap_or(&0);
            skip_keys.remove(&oldest);
        }

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
        let (_nonce_gen, seq) = self.validate_and_extract_nonce(nonce)?;

        // Build AAD from rekey parameters. The AEAD tag will cryptographically
        // bind the rekey payload to this ciphertext — an attacker who strips
        // and replaces the rekey params will cause AEAD verification to fail.
        let aad = build_rekey_aad(
            rekey_ciphertext,
            rekey_x25519_pk.map(|x| x.as_slice()),
            rekey_mlkem_pk,
        );

        // Phase 1: Tentatively derive the INCOMING proposal from the rekey payload.
        // No active state is mutated here; on AEAD failure everything is rolled back.
        if let (Some(ct), Some(xpk), Some(mpk)) =
            (rekey_ciphertext, rekey_x25519_pk, rekey_mlkem_pk)
        {
            let ss = decapsulate_hybrid(
                ct,
                &self.our_hybrid_pair.x25519_sk,
                &self.our_hybrid_pair.mlkem_sk,
            )?;
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
                    if let Ok(pending_msg_key) = derive_tentative_msg_key(
                        &pending_recv_key,
                        self.recv_message_count,
                        seq,
                        self.max_skip,
                    ) {
                        // Single-pass: verify AEAD AND capture plaintext in one call
                        if let Ok(plaintext) = decrypt_chacha20(&pending_msg_key, nonce, ciphertext, &aad) {
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
                            // Advance receiving chain directly — no double-decrypt
                            let (next_ck, new_skip) = advance_receiving_chain(
                                &self.receiving_chain_key,
                                self.recv_message_count,
                                seq,
                                self.max_skip,
                            )?;
                            self.receiving_chain_key = next_ck;
                            self.recv_message_count = seq + 1;
                            let store = self.skip_message_keys.as_mut().unwrap();
                            for (k, v) in new_skip {
                                store.insert(k, zeroize::Zeroizing::new(v));
                            }
                            while store.len() > self.max_skip {
                                let oldest = *store.keys().min().unwrap_or(&0);
                                store.remove(&oldest);
                            }
                            self.seen_sequence_numbers.insert(seq);
                            let lower_bound = self.recv_message_count.saturating_sub((self.max_skip * 2) as u64);
                            self.seen_sequence_numbers.retain(|&s| s >= lower_bound);
                            return Ok(plaintext);
                        }
                    }
                }
                // AEAD failed — roll back ALL pending proposal state to prevent
                // replayed/tampered rekey payloads from corrupting the session.
                self.pending_root_key = None;
                self.pending_sending_chain_key = None;
                self.pending_receiving_chain_key = None;
                self.pending_peer_x25519_pk = None;
                self.pending_peer_mlkem_pk = None;
                self.pending_generation_bump = false;
                self.pending_rekey_carrier_seq = None;
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
            return Err(KyberError::CryptoError("Ratchet generation at u32::MAX — nonce reuse risk. Re-pair required.".into()));
        }
        if nonce_gen != self.ratchet_generation && nonce_gen != self.ratchet_generation.saturating_add(1) {
            return Err(KyberError::CryptoError(format!(
                "Nonce generation mismatch: expected {} or {}, got {}",
                self.ratchet_generation, self.ratchet_generation.saturating_add(1), nonce_gen
            )));
        }

        if self.seen_sequence_numbers.contains(&seq) {
            return Err(KyberError::CryptoError(format!("Duplicate sequence number {} detected (replay attack)", seq)));
        }

        Ok((nonce_gen, seq))
    }
}

impl DoubleRatchetState {
    /// Explicit session resync after a gap exceeded `max_skip` (e.g. a Wi-Fi →
    /// cellular handoff dropped a burst of messages). Derives skip keys for the
    /// missed range and advances the receiving chain to `target_seq`.
    ///
    /// SECURITY: only call this AFTER the peer's Synchronize request has been
    /// authenticated (it must arrive ratchet-encrypted, i.e. verified AEAD).
    /// The forward gap is bounded by SYNC_MAX_GAP so a compromised peer cannot
    /// force unbounded KDF work.
    pub fn resync_receiving_chain(&mut self, target_seq: u64) -> Result<u64, KyberError> {
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
        let mut ck = self.receiving_chain_key;
        let mut skip_keys = HashMap::new();
        for skip_seq in cur..target_seq {
            let hk = Hkdf::<Sha256>::new(Some(&ck), b"step");
            let mut skip_key = [0u8; 32];
            hk.expand(b"kyberpipe-msg-key", &mut skip_key)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            hk.expand(b"kyberpipe-next-chain", &mut ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            skip_keys.insert(skip_seq, skip_key);
        }
        // After skipping `cur..target_seq`, the chain is positioned at
        // `target_seq` — the first non-missed message decrypts from here, so the
        // receiving chain key stays at `ck` and recv_message_count = target_seq.
        self.receiving_chain_key = ck;
        self.recv_message_count = target_seq;
        let store = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;
        for (k, v) in skip_keys {
            store.insert(k, zeroize::Zeroizing::new(v));
        }
        while store.len() > self.max_skip {
            let oldest = *store.keys().min().unwrap_or(&0);
            store.remove(&oldest);
        }
        Ok(gap)
    }
}
