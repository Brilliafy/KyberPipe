use super::{
    decapsulate_hybrid, decrypt_chacha20, encapsulate_hybrid, encrypt_chacha20,
    generate_hybrid_keypair, generate_nonce_from_seq, HybridKemResult, HybridKeyPair, KyberError,
    RATCHET_REKEY_INTERVAL,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Represents an encrypted ratchet message with optional DH re-key payload
pub struct RatchetEncryptedMessage {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    /// If Some, this message includes a new ephemeral public key for DH ratchet re-key
    pub rekey_x25519_pk: Option<[u8; 32]>,
    pub rekey_mlkem_pk: Option<Vec<u8>>,
    pub rekey_ciphertext: Option<Vec<u8>>,
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
    pub ratchet_generation: u64,
    /// Pending root key derived from received rekey payload (not yet confirmed)
    pub pending_root_key: Option<[u8; 32]>,
    pub pending_sending_chain_key: Option<[u8; 32]>,
    pub pending_receiving_chain_key: Option<[u8; 32]>,
    #[zeroize(skip)]
    pub skip_message_keys: Option<HashMap<u64, Zeroizing<[u8; 32]>>>,
    pub max_skip: usize,
    /// Historical keypairs from previous ratchet generations — kept until peer acknowledges
    /// the new generation by sending a message encrypted under the new chain.
    #[zeroize(skip)]
    pub previous_keypairs: VecDeque<HybridKeyPair>,
    pub max_key_history: usize,
    /// True after a rekey commit, cleared when a message is received from the
    /// peer using the new chain (proving they processed the rekey).
    pub rekey_pending_confirm: bool,
}

// ────────────────────────────────────────────────────────────
// Rekey AAD helpers — bind rekey parameters into the AEAD tag
// to prevent attackers from swapping rekey payloads.
// ────────────────────────────────────────────────────────────

/// Build AAD from rekey parameters. Empty if no rekey payload.
fn build_rekey_aad(
    rekey_ciphertext: Option<&[u8]>,
    rekey_x25519_pk: Option<&[u8; 32]>,
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
    /// Decrypt with AAD. Uses the same chain logic as try_decrypt_with_chain
    /// but passes `aad` to the AEAD verification.
    fn try_decrypt_with_chain_aad(
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
                return Err(KyberError::CryptoError(format!(
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
            hk.expand(b"kyberpipe-next-recv-chain", &mut tentative_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            tentative_skip.insert(skip_seq, skip_key);
        }

        let hk = Hkdf::<Sha256>::new(Some(&tentative_ck), b"step");
        let mut target_msg_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut target_msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        let mut next_ck = [0u8; 32];
        hk.expand(b"kyberpipe-next-recv-chain", &mut next_ck)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        // AEAD decryption with AAD — if rekey params were tampered, this fails.
        let plaintext = decrypt_chacha20(&target_msg_key, nonce, ciphertext, aad)?;

        // AEAD verified — COMMIT state
        self.receiving_chain_key = next_ck;
        self.recv_message_count = seq + 1;
        self.rekey_pending_confirm = false;
        for (k, v) in tentative_skip {
            skip_keys.insert(k, Zeroizing::new(v));
        }
        while skip_keys.len() > self.max_skip {
            let oldest = *skip_keys.keys().min().unwrap_or(&0);
            skip_keys.remove(&oldest);
        }

        Ok(plaintext)
    }

    /// Initialize a Double Ratchet session from a master shared secret.
    /// Uses two-phase KDF for domain separation between root key and chain keys.
    pub fn new(master_shared_secret: &[u8], is_initiator: bool) -> Result<Self, KyberError> {
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
            our_hybrid_pair: generate_hybrid_keypair(),
            peer_x25519_pk: None,
            peer_mlkem_pk: None,
            rekey_interval: RATCHET_REKEY_INTERVAL,
            ratchet_generation: 0,
            pending_root_key: None,
            pending_sending_chain_key: None,
            pending_receiving_chain_key: None,
            skip_message_keys: Some(HashMap::new()),
            max_skip: 100,
            previous_keypairs: VecDeque::new(),
            max_key_history: 3,
            rekey_pending_confirm: false,
        })
    }

    /// Advance sending symmetric chain key and encrypt plaintext payload.
    /// Every `rekey_interval` messages, generates a DH re-key payload attached to the message.
    /// The re-key does NOT take effect until the next call — the current message is encrypted
    /// with the old chain. Call commit_pending_rekey() before the next encrypt to switch.
    /// Returns the encrypted message with optional re-key payload.
    pub fn ratchet_encrypt(
        &mut self,
        plaintext: &[u8],
    ) -> Result<RatchetEncryptedMessage, KyberError> {
        let seq = self.send_message_count;
        self.send_message_count += 1;

        let nonce = generate_nonce_from_seq(seq);

        // Auto-rekey: generate new keys and commit immediately
        let (rekey_x25519_pk, rekey_mlkem_pk, rekey_ciphertext) =
            if seq > 0 && seq.is_multiple_of(self.rekey_interval) && !self.rekey_pending_confirm {
                if let (Some(peer_xpk), Some(ref peer_mpk)) =
                    (self.peer_x25519_pk, self.peer_mlkem_pk.clone())
                {
                    let our_new = generate_hybrid_keypair();
                    let new_x25519_pk = our_new.x25519_pk;
                    let new_mlkem_pk = our_new.mlkem_pk.clone();
                    let kem_res = encapsulate_hybrid(&peer_xpk, peer_mpk)?;

                    // Derive new root + chains but store as PENDING — don't switch yet
                    let hk2 = Hkdf::<Sha256>::new(
                        Some(&self.root_key),
                        &kem_res.combined_shared_secret.clone(),
                    );
                    let mut new_root = [0u8; 32];
                    let mut new_send = [0u8; 32];
                    let mut new_recv = [0u8; 32];
                    hk2.expand(b"kyberpipe-next-root-key", &mut new_root)
                        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
                    hk2.expand(b"kyberpipe-next-send-chain-from-rekey", &mut new_send)
                        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
                    hk2.expand(b"kyberpipe-next-recv-chain-from-rekey", &mut new_recv)
                        .map_err(|e| KyberError::CryptoError(e.to_string()))?;

                    self.ratchet_generation += 1;
                    // Commit rekey immediately and set pending confirm flag.
                    // The next received message will clear this flag, proving the
                    // peer processed the rekey. Without confirmation, we won't
                    // rekey again — preventing desync from missed rekey messages.
                    self.root_key = new_root;
                    self.sending_chain_key = new_send;
                    self.receiving_chain_key = new_recv;
                    self.rekey_pending_confirm = true;
                    // Push current keypair to history before replacing
                    let old_pair = std::mem::replace(&mut self.our_hybrid_pair, our_new);
                    self.previous_keypairs.push_back(old_pair);
                    while self.previous_keypairs.len() > self.max_key_history {
                        self.previous_keypairs.pop_front();
                    }

                    (
                        Some(new_x25519_pk),
                        Some(new_mlkem_pk),
                        Some(kem_res.ciphertext_bytes.clone()),
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

        // Build AAD from rekey parameters to bind them into the AEAD tag
        let aad = build_rekey_aad(
            rekey_ciphertext.as_deref(),
            rekey_x25519_pk.as_ref(),
            rekey_mlkem_pk.as_deref(),
        );

        // Derive message key and next chain key from the current (or newly committed) chain
        let hk = Hkdf::<Sha256>::new(Some(&self.sending_chain_key), b"step");
        let mut msg_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-send-chain", &mut self.sending_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        let ciphertext = encrypt_chacha20(&msg_key, &nonce, plaintext, &aad)?;

        Ok(RatchetEncryptedMessage {
            nonce,
            ciphertext,
            rekey_x25519_pk,
            rekey_mlkem_pk,
            rekey_ciphertext,
        })
    }

    /// Commit any pending re-key so the new chain takes effect immediately.
    pub fn commit_pending_rekey(&mut self) {
        if let (Some(pk), Some(psk), Some(prk)) = (
            self.pending_root_key,
            self.pending_sending_chain_key,
            self.pending_receiving_chain_key,
        ) {
            self.root_key = pk;
            self.sending_chain_key = psk;
            self.receiving_chain_key = prk;
            self.pending_root_key = None;
            self.pending_sending_chain_key = None;
            self.pending_receiving_chain_key = None;
        }
    }

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
        let seq = u64::from_be_bytes([
            nonce[4], nonce[5], nonce[6], nonce[7], nonce[8], nonce[9], nonce[10], nonce[11],
        ]);

        let skip_keys = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;

        // If this sequence number has a cached key, use it directly
        if let Some(cached_key) = skip_keys.remove(&seq) {
            return decrypt_chacha20(&cached_key, nonce, ciphertext, aad);
        }

        // Attempt decryption with current chain.
        let result = self.try_decrypt_with_chain(seq, nonce, ciphertext, false, aad);

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
                        // Verify AEAD with AAD — if rekey params were tampered, this fails
                        if decrypt_chacha20(&pending_msg_key, nonce, ciphertext, aad).is_ok() {
                            self.commit_pending_rekey();
                            return self.try_decrypt_with_chain(seq, nonce, ciphertext, true, aad);
                        }
                    }
                }
                Err(first_err)
            }
        }
    }

    /// Internal: attempt decryption with current chain. If `is_retry` is false,
    /// derives keys tentatively and only commits on success. If true, assumes
    /// state has already been committed and operates on active chain.
    fn try_decrypt_with_chain(
        &mut self,
        seq: u64,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        _is_retry: bool,
        aad: &[u8],
    ) -> Result<Vec<u8>, KyberError> {
        let skip_keys = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;

        if seq > self.recv_message_count {
            let diff = (seq - self.recv_message_count) as usize;
            if diff > self.max_skip {
                return Err(KyberError::CryptoError(format!(
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
            hk.expand(b"kyberpipe-next-recv-chain", &mut tentative_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            tentative_skip.insert(skip_seq, skip_key);
        }

        let hk = Hkdf::<Sha256>::new(Some(&tentative_ck), b"step");
        let mut target_msg_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut target_msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        let mut next_ck = [0u8; 32];
        hk.expand(b"kyberpipe-next-recv-chain", &mut next_ck)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        let plaintext = decrypt_chacha20(&target_msg_key, nonce, ciphertext, aad)?;

        // AEAD verified — COMMIT state
        self.receiving_chain_key = next_ck;
        self.recv_message_count = seq + 1;
        self.rekey_pending_confirm = false;
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
    /// If rekey payload is present, decapsulate it and store derived keys as pending.
    /// Decryption automatically tries the pending chain as fallback.
    pub fn ratchet_decrypt_with_rekey(
        &mut self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        rekey_ciphertext: Option<&[u8]>,
        rekey_x25519_pk: Option<&[u8; 32]>,
        rekey_mlkem_pk: Option<&[u8]>,
    ) -> Result<Vec<u8>, KyberError> {
        // Build AAD from rekey parameters. The AEAD tag will cryptographically
        // bind the rekey payload to this ciphertext — an attacker who strips
        // and replaces the rekey params will cause AEAD verification to fail.
        let aad = build_rekey_aad(rekey_ciphertext, rekey_x25519_pk, rekey_mlkem_pk);

        // Decrypt with the built AAD. If the rekey params were tampered with,
        // the AEAD tag won't match and decryption will fail.
        let plaintext = self.try_decrypt_with_chain_aad(
            u64::from_be_bytes([
                nonce[4], nonce[5], nonce[6], nonce[7], nonce[8], nonce[9], nonce[10], nonce[11],
            ]),
            nonce,
            ciphertext,
            &aad,
        )?;

        // Only after successful decryption do we process the rekey payload.
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
            self.pending_root_key = Some(new_root);
            self.pending_sending_chain_key = Some(new_send);
            self.pending_receiving_chain_key = Some(new_recv);
            self.peer_x25519_pk = Some(*xpk);
            self.peer_mlkem_pk = Some(mpk.to_vec());
            self.ratchet_generation += 1;
        }

        Ok(plaintext)
    }

    /// Perform a Post-Quantum Ephemeral DH/KEM Ratchet re-key step.
    /// Derives new keys into pending_* fields — does NOT overwrite active state
    /// until peer acknowledgment via commit_pending_rekey().
    pub fn dh_ratchet_rekey(
        &mut self,
        peer_x25519_pk: [u8; 32],
        peer_mlkem_pk: &[u8],
    ) -> Result<HybridKemResult, KyberError> {
        let kem_res = encapsulate_hybrid(&peer_x25519_pk, peer_mlkem_pk)?;

        let hk = Hkdf::<Sha256>::new(
            Some(&self.root_key),
            &kem_res.combined_shared_secret.clone(),
        );
        let mut new_root = [0u8; 32];
        let mut new_send = [0u8; 32];
        let mut new_recv = [0u8; 32];
        hk.expand(b"kyberpipe-next-root-key", &mut new_root)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-send-chain-from-rekey", &mut new_send)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-recv-chain-from-rekey", &mut new_recv)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        // Store as pending — don't overwrite active state until peer acknowledges
        self.pending_root_key = Some(new_root);
        self.pending_sending_chain_key = Some(new_send);
        self.pending_receiving_chain_key = Some(new_recv);
        self.peer_x25519_pk = Some(peer_x25519_pk);
        self.peer_mlkem_pk = Some(peer_mlkem_pk.to_vec());
        let old_pair = std::mem::replace(&mut self.our_hybrid_pair, generate_hybrid_keypair());
        self.previous_keypairs.push_back(old_pair);
        while self.previous_keypairs.len() > self.max_key_history {
            self.previous_keypairs.pop_front();
        }

        Ok(kem_res)
    }
}

/// Derive sending and receiving chain keys from the root key with domain separation.
fn derive_chain_keys_from_root(
    root_key: &[u8; 32],
    send_label: &[u8],
    recv_label: &[u8],
) -> Result<([u8; 32], [u8; 32]), KyberError> {
    let mut send_ck = [0u8; 32];
    let mut recv_ck = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"kyberpipe-chain-salt"), root_key)
        .expand(send_label, &mut send_ck)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
    Hkdf::<Sha256>::new(Some(b"kyberpipe-chain-salt"), root_key)
        .expand(recv_label, &mut recv_ck)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
    Ok((send_ck, recv_ck))
}

/// Derive a message key from a receiving chain key at a given sequence offset.
/// Non-mutating helper used by the pending chain AEAD verification fallback.
fn derive_tentative_msg_key(
    recv_chain_key: &[u8; 32],
    recv_message_count: u64,
    target_seq: u64,
    max_skip: usize,
) -> Result<[u8; 32], KyberError> {
    if target_seq > recv_message_count {
        let diff = (target_seq - recv_message_count) as usize;
        if diff > max_skip {
            return Err(KyberError::CryptoError(format!(
                "Tentative derivation gap {} exceeds max_skip {}",
                diff, max_skip
            )));
        }
    }
    let mut ck = *recv_chain_key;
    for _ in recv_message_count..target_seq {
        let hk = Hkdf::<Sha256>::new(Some(&ck), b"step");
        let mut next_ck = [0u8; 32];
        hk.expand(b"kyberpipe-next-recv-chain", &mut next_ck)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        ck = next_ck;
    }
    let hk = Hkdf::<Sha256>::new(Some(&ck), b"step");
    let mut msg_key = [0u8; 32];
    hk.expand(b"kyberpipe-msg-key", &mut msg_key)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;
    Ok(msg_key)
}
