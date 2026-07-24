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
}

impl DoubleRatchetState {
    /// Initialize a Double Ratchet session from a master shared secret.
    /// Uses two-phase KDF for domain separation between root key and chain keys.
    pub fn new(master_shared_secret: &[u8], is_initiator: bool) -> Result<Self, KyberError> {
        // Phase 1: Extract master seed from shared secret
        let hk = Hkdf::<Sha256>::new(Some(b"kyberpipe-pq-ratchet-salt"), master_shared_secret);
        let mut master_seed = [0u8; 32];
        hk.expand(b"kyberpipe-master-seed", &mut master_seed)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        // Phase 2: Derive root key from master seed (domain-separated from chain keys)
        let root_hk = Hkdf::<Sha256>::new(Some(b"kyberpipe-root-salt"), &master_seed);
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
        let hk = Hkdf::<Sha256>::new(Some(&self.sending_chain_key), b"step");
        let mut msg_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-send-chain", &mut self.sending_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        let seq = self.send_message_count;
        self.send_message_count += 1;

        let nonce = generate_nonce_from_seq(seq);

        let ciphertext = encrypt_chacha20(&msg_key, &nonce, plaintext)?;

        // Auto-rekey: generate new keys but store as pending, encrypt with OLD chain
        let (rekey_x25519_pk, rekey_mlkem_pk, rekey_ciphertext) =
            if seq > 0 && seq.is_multiple_of(self.rekey_interval) {
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

                    self.pending_root_key = Some(new_root);
                    self.pending_sending_chain_key = Some(new_send);
                    self.pending_receiving_chain_key = Some(new_recv);
                    self.ratchet_generation += 1;
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
        let seq = u64::from_be_bytes([
            nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
        ]);

        let skip_keys = self
            .skip_message_keys
            .as_mut()
            .ok_or_else(|| KyberError::CryptoError("Skip key store already consumed".into()))?;

        // If this sequence number has a cached key, use it directly
        if let Some(cached_key) = skip_keys.remove(&seq) {
            return decrypt_chacha20(&cached_key, nonce, ciphertext);
        }

        // Attempt decryption with current chain.
        let result = self.try_decrypt_with_chain(seq, nonce, ciphertext, false);

        match result {
            Ok(plaintext) => Ok(plaintext),
            Err(first_err) => {
                // If pending keys exist, verify AEAD on pending chain BEFORE committing
                if let Some(pending_recv_key) = self.pending_receiving_chain_key {
                    // Derive msg key from pending chain (non-mutating, sandboxed)
                    if let Ok(pending_msg_key) =
                        derive_tentative_msg_key(&pending_recv_key, self.recv_message_count, seq)
                    {
                        // Verify AEAD in memory — only commit if decryption succeeds
                        if decrypt_chacha20(&pending_msg_key, nonce, ciphertext).is_ok() {
                            self.commit_pending_rekey();
                            return self.try_decrypt_with_chain(seq, nonce, ciphertext, true);
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

        let plaintext = decrypt_chacha20(&target_msg_key, nonce, ciphertext)?;

        // AEAD verified — COMMIT state
        self.receiving_chain_key = next_ck;
        self.recv_message_count = seq + 1;
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
        // If rekey payload present, decapsulate to derive new root chain
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
        // Decrypt with old chain
        self.ratchet_decrypt(nonce, ciphertext)
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
) -> Result<[u8; 32], KyberError> {
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
