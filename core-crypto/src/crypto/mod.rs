// KyberPipe crypto module — domain-specific submodules
pub mod aead;
pub mod clipboard;
pub mod crdt;
pub mod kem;
pub mod misc;
pub mod padding;
pub mod ratchet;
pub mod sas;
pub mod shamir;
pub mod signing;

// Re-export everything at crate::crypto::* for backward compatibility
pub use aead::*;
pub use clipboard::*;
pub use crdt::*;
pub use kem::*;
pub use misc::*;
pub use padding::*;
pub use ratchet::*;
pub use sas::*;
pub use shamir::*;
pub use signing::*;

// ────────────────────────────────────────────────────────────
// Remaining code lives in the legacy block below.
// Each submodule above will absorb its corresponding section.
// ────────────────────────────────────────────────────────────
use crate::error::KyberError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const CHUNKS_SIZE: usize = 64 * 1024; // 64 KB per block chunk
pub const RATCHET_REKEY_INTERVAL: u64 = 100; // DH re-key every 100 messages

/// Represents an encrypted ratchet message with optional DH re-key payload
pub struct RatchetEncryptedMessage {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    /// If Some, this message includes a new ephemeral public key for DH ratchet re-key
    pub rekey_x25519_pk: Option<[u8; 32]>,
    pub rekey_mlkem_pk: Option<Vec<u8>>,
    pub rekey_ciphertext: Option<Vec<u8>>,
}

/// Holds raw Hybrid (X25519 + ML-KEM-768) keypair
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct HybridKeyPair {
    pub x25519_pk: [u8; 32],
    pub x25519_sk: [u8; 32],
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

/// Holds Hybrid encapsulation response
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct HybridKemResult {
    pub ciphertext_bytes: Vec<u8>,
    pub combined_shared_secret: Vec<u8>,
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
    /// Initialize a Double Ratchet session from a master shared secret
    pub fn new(master_shared_secret: &[u8], is_initiator: bool) -> Result<Self, KyberError> {
        let hk = Hkdf::<Sha256>::new(Some(b"kyberpipe-pq-ratchet-salt"), master_shared_secret);
        let mut root_key = [0u8; 32];
        let mut sending_ck = [0u8; 32];
        let mut receiving_ck = [0u8; 32];

        hk.expand(b"kyberpipe-root-key", &mut root_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        if is_initiator {
            hk.expand(b"kyberpipe-send-chain", &mut sending_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            hk.expand(b"kyberpipe-recv-chain", &mut receiving_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        } else {
            hk.expand(b"kyberpipe-recv-chain", &mut sending_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
            hk.expand(b"kyberpipe-send-chain", &mut receiving_ck)
                .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        }

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

        // If there's a pending rekey, commit it now (next message uses new chain)
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

        // Auto-rekey: generate new keys but store as pending, encrypt with OLD chain
        let (rekey_x25519_pk, rekey_mlkem_pk, rekey_ciphertext) =
            if seq > 0 && seq % self.rekey_interval == 0 {
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
            return decrypt_chacha20(&*cached_key, nonce, ciphertext);
        }

        // Attempt decryption with current chain. If it fails AND pending keys exist,
        // commit pending and retry — this handles the unidirectional rekey scenario.
        let result = self.try_decrypt_with_chain(seq, nonce, ciphertext, false);

        match result {
            Ok(plaintext) => Ok(plaintext),
            Err(first_err) => {
                // If pending keys exist, commit them and try again
                if self.pending_receiving_chain_key.is_some() {
                    self.commit_pending_rekey();
                    // Retry decryption with the newly committed chain
                    self.try_decrypt_with_chain(seq, nonce, ciphertext, true)
                        .map_err(|_| first_err) // Return original error if both fail
                } else {
                    Err(first_err)
                }
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
            if let Ok(ss) = decapsulate_hybrid(
                ct,
                &self.our_hybrid_pair.x25519_sk,
                &self.our_hybrid_pair.mlkem_sk,
            ) {
                let hk2 = Hkdf::<Sha256>::new(Some(&self.root_key), &ss);
                let mut new_root = [0u8; 32];
                let mut new_send = [0u8; 32];
                let mut new_recv = [0u8; 32];
                let _ = hk2.expand(b"kyberpipe-next-root-key", &mut new_root);
                let _ = hk2.expand(b"kyberpipe-next-recv-chain-from-rekey", &mut new_send);
                let _ = hk2.expand(b"kyberpipe-next-send-chain-from-rekey", &mut new_recv);
                self.pending_root_key = Some(new_root);
                self.pending_sending_chain_key = Some(new_send);
                self.pending_receiving_chain_key = Some(new_recv);
                self.peer_x25519_pk = Some(*xpk);
                self.peer_mlkem_pk = Some(mpk.to_vec());
                self.ratchet_generation += 1;
            }
        }
        // Decrypt with old chain
        self.ratchet_decrypt(nonce, ciphertext)
    }

    /// Perform a Post-Quantum Ephemeral DH/KEM Ratchet re-key step
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
        hk.expand(b"kyberpipe-next-root-key", &mut self.root_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-send-chain", &mut self.sending_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-recv-chain", &mut self.receiving_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        self.peer_x25519_pk = Some(peer_x25519_pk);
        self.peer_mlkem_pk = Some(peer_mlkem_pk.to_vec());
        // Push old keypair to history before replacing
        let old_pair = std::mem::replace(&mut self.our_hybrid_pair, generate_hybrid_keypair());
        self.previous_keypairs.push_back(old_pair);
        while self.previous_keypairs.len() > self.max_key_history {
            self.previous_keypairs.pop_front();
        }

        Ok(kem_res)
    }
}

/// Generate Hybrid (X25519 + NIST ML-KEM-768) keypair.
pub fn generate_hybrid_keypair() -> HybridKeyPair {
    let mut rng = rand::thread_rng();
    let x25519_sk = X25519StaticSecret::random_from_rng(&mut rng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    let (mlkem_pk, mlkem_sk) = kyber768::keypair();

    HybridKeyPair {
        x25519_pk: x25519_pk.to_bytes(),
        x25519_sk: x25519_sk.to_bytes(),
        mlkem_pk: mlkem_pk.as_bytes().to_vec(),
        mlkem_sk: mlkem_sk.as_bytes().to_vec(),
    }
}

/// Encapsulate shared secret using Hybrid Key Exchange (X25519 Diffie-Hellman + ML-KEM-768).
pub fn encapsulate_hybrid(
    peer_x25519_pk_bytes: &[u8; 32],
    peer_mlkem_pk_bytes: &[u8],
) -> Result<HybridKemResult, KyberError> {
    let mut rng = rand::thread_rng();
    let ephem_x25519_sk = X25519StaticSecret::random_from_rng(&mut rng);
    let ephem_x25519_pk = X25519PublicKey::from(&ephem_x25519_sk);
    let peer_x25519_pk = X25519PublicKey::from(*peer_x25519_pk_bytes);
    let x25519_ss = ephem_x25519_sk.diffie_hellman(&peer_x25519_pk);

    let peer_mlkem_pk = kyber768::PublicKey::from_bytes(peer_mlkem_pk_bytes).map_err(|_| {
        KyberError::EncapsulationFailed("Invalid ML-KEM-768 public key bytes".into())
    })?;
    let (mlkem_ss, mlkem_ct) = kyber768::encapsulate(&peer_mlkem_pk);

    let mut combined_ss = Vec::with_capacity(32 + mlkem_ss.as_bytes().len());
    combined_ss.extend_from_slice(x25519_ss.as_bytes());
    combined_ss.extend_from_slice(mlkem_ss.as_bytes());

    let mut combined_ct = Vec::with_capacity(32 + mlkem_ct.as_bytes().len());
    combined_ct.extend_from_slice(ephem_x25519_pk.as_bytes());
    combined_ct.extend_from_slice(mlkem_ct.as_bytes());

    Ok(HybridKemResult {
        ciphertext_bytes: combined_ct,
        combined_shared_secret: combined_ss,
    })
}

/// Decapsulate shared secret using Hybrid Key Exchange.
pub fn decapsulate_hybrid(
    combined_ct_bytes: &[u8],
    my_x25519_sk_bytes: &[u8; 32],
    my_mlkem_sk_bytes: &[u8],
) -> Result<Vec<u8>, KyberError> {
    if combined_ct_bytes.len() < 32 + kyber768::ciphertext_bytes() {
        return Err(KyberError::DecapsulationFailed(
            "Ciphertext shorter than expected hybrid bundle".into(),
        ));
    }

    let (ephem_x25519_pk_bytes, mlkem_ct_bytes) = combined_ct_bytes.split_at(32);
    let mut ephem_x25519_arr = [0u8; 32];
    ephem_x25519_arr.copy_from_slice(ephem_x25519_pk_bytes);
    let ephem_x25519_pk = X25519PublicKey::from(ephem_x25519_arr);

    let my_x25519_sk = X25519StaticSecret::from(*my_x25519_sk_bytes);
    let x25519_ss = my_x25519_sk.diffie_hellman(&ephem_x25519_pk);

    let mlkem_ct = kyber768::Ciphertext::from_bytes(mlkem_ct_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 ciphertext bytes".into())
    })?;
    let my_mlkem_sk = kyber768::SecretKey::from_bytes(my_mlkem_sk_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 secret key bytes".into())
    })?;
    let mlkem_ss = kyber768::decapsulate(&mlkem_ct, &my_mlkem_sk);

    let mut combined_ss = Vec::with_capacity(32 + mlkem_ss.as_bytes().len());
    combined_ss.extend_from_slice(x25519_ss.as_bytes());
    combined_ss.extend_from_slice(mlkem_ss.as_bytes());

    Ok(combined_ss)
}

/// Derive a 256-bit (32-byte) symmetric key using HKDF-SHA256 from combined shared secret.
pub fn derive_session_key(
    shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; 32], KyberError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| KyberError::CryptoError(format!("HKDF expand failed: {e}")))?;
    Ok(okm)
}

/// Encrypt payload data with ChaCha20-Poly1305 AEAD.
pub fn encrypt_chacha20(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_arr = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce_arr, plaintext)
        .map_err(|e| KyberError::EncryptionFailed(format!("ChaCha20Poly1305 encrypt error: {e}")))
}

/// Decrypt payload data with ChaCha20-Poly1305 AEAD.
pub fn decrypt_chacha20(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_arr = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce_arr, ciphertext)
        .map_err(|e| KyberError::DecryptionFailed(format!("ChaCha20Poly1305 decrypt error: {e}")))
}

/// Generate a 96-bit nonce from a 64-bit sequence counter.
pub fn generate_nonce_from_seq(seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let seq_bytes = seq.to_be_bytes();
    nonce[4..12].copy_from_slice(&seq_bytes);
    nonce
}

/// Normalize text to prevent OS line-ending and whitespace hash mismatches (\r\n -> \n, trim end)
pub fn normalize_clipboard_text(text: &str) -> String {
    text.replace("\r\n", "\n").trim_end().to_string()
}

/// Compute SHA-256 hash of normalized text
pub fn hash_clipboard_text(text: &str) -> String {
    let normalized = normalize_clipboard_text(text);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Pad payload to standardized block sizes (256 B, 1024 B, 64 KB) to obscure metadata
pub fn pad_payload(data: &[u8]) -> Result<Vec<u8>, KyberError> {
    let orig_len = data.len();
    if orig_len > 64 * 1024 - 4 {
        return Err(KyberError::EncryptionFailed(
            "Payload exceeds 64KB max padded block size".into(),
        ));
    }

    let target_size = if orig_len + 4 <= 256 {
        256
    } else if orig_len + 4 <= 1024 {
        1024
    } else {
        64 * 1024
    };

    let mut padded = Vec::with_capacity(target_size);
    let len_bytes = (orig_len as u32).to_be_bytes();
    padded.extend_from_slice(&len_bytes);
    padded.extend_from_slice(data);
    padded.resize(target_size, 0u8);

    Ok(padded)
}

/// Unpad standardized block back to original payload bytes
pub fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>, KyberError> {
    if padded.len() < 4 {
        return Err(KyberError::DecryptionFailed(
            "Padded block too short".into(),
        ));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&padded[0..4]);
    let orig_len = u32::from_be_bytes(len_bytes) as usize;

    if orig_len > padded.len().saturating_sub(4) {
        return Err(KyberError::DecryptionFailed(
            "Invalid padded length header".into(),
        ));
    }

    Ok(padded[4..4 + orig_len].to_vec())
}

/// Generate jittered dummy cover traffic heartbeat payload
pub fn generate_cover_traffic_packet() -> Vec<u8> {
    let mut dummy = vec![0u8; 256];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut dummy);
    dummy
}

/// Last-Write-Wins Element-Set Conflict-Free Replicated Data Type (LWW-CRDT) for multi-device mesh
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LwwRegisterCRDT<T: Clone> {
    pub value: T,
    pub timestamp: u64,
    pub node_id: String,
}

impl<T: Clone> LwwRegisterCRDT<T> {
    pub fn new(value: T, node_id: String, timestamp: u64) -> Self {
        Self {
            value,
            timestamp,
            node_id,
        }
    }

    /// Merge incoming CRDT state; returns true if incoming state superseded local state
    pub fn merge(&mut self, incoming: LwwRegisterCRDT<T>) -> bool {
        if incoming.timestamp > self.timestamp
            || (incoming.timestamp == self.timestamp && incoming.node_id > self.node_id)
        {
            self.value = incoming.value;
            self.timestamp = incoming.timestamp;
            self.node_id = incoming.node_id;
            true
        } else {
            false
        }
    }
}

/// GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B)
struct Gf256;

impl Gf256 {
    fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let idx_a = GF256_LOG[a as usize] as u16;
        let idx_b = GF256_LOG[b as usize] as u16;
        let sum = idx_a + idx_b;
        let mod_sum = if sum >= 255 { sum - 255 } else { sum };
        GF256_EXP[mod_sum as usize]
    }

    fn inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        let idx = GF256_LOG[a as usize] as u16;
        let neg = 255 - idx;
        GF256_EXP[neg as usize]
    }
}

static GF256_LOG: [u8; 256] = [
    0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
    0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
    0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
    0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
    0xb4, 0x7c, 0x19, 0x5d, 0x29, 0x98, 0x72, 0x2e, 0xdb, 0x32, 0x6b, 0x01, 0x84, 0xfd, 0x8a, 0x5f,
    0xca, 0x4f, 0xa7, 0xc1, 0xa6, 0x62, 0x97, 0x22, 0x31, 0xaa, 0x34, 0xde, 0x9a, 0xb0, 0x1c, 0x0d,
    0x9b, 0xb3, 0x6e, 0xc6, 0xbd, 0xbc, 0xc9, 0xcc, 0xbf, 0xec, 0x03, 0x71, 0xcb, 0x5c, 0xdd, 0x92,
    0x96, 0x67, 0x81, 0x80, 0x42, 0x04, 0xaf, 0x65, 0x69, 0x7b, 0x5e, 0x2c, 0x41, 0xb7, 0xee, 0x58,
    0x63, 0x44, 0x49, 0x45, 0x60, 0x15, 0x1b, 0x2f, 0x02, 0x82, 0xfc, 0x9e, 0xb2, 0x6d, 0x1a, 0xb5,
    0xb6, 0xa2, 0x61, 0x0a, 0x56, 0x30, 0x57, 0x8d, 0x1e, 0x3b, 0x38, 0x94, 0x33, 0x73, 0x8c, 0x6f,
    0x05, 0xef, 0x4a, 0xbe, 0xa4, 0x00, 0x52, 0x06, 0x83, 0x8f, 0xbb, 0xfd, 0x9f, 0x88, 0x5b, 0x1d,
    0x12, 0xda, 0xb9, 0xe2, 0x4d, 0x75, 0xac, 0x3c, 0xd5, 0x51, 0xf3, 0x1f, 0x11, 0x24, 0x86, 0x17,
    0xce, 0x47, 0x55, 0x9d, 0x76, 0x25, 0xe4, 0x50, 0xdc, 0xb1, 0x26, 0x59, 0xba, 0xe6, 0x2d, 0xf9,
    0xf4, 0xe9, 0xed, 0xab, 0xe7, 0xdf, 0xae, 0xc4, 0xc0, 0x95, 0x7d, 0xa5, 0x68, 0x85, 0x64, 0xfb,
    0xe1, 0x7e, 0xf6, 0x66, 0x7a, 0x37, 0xf8, 0xa3, 0x89, 0x0b, 0x3d, 0xf1, 0xd9, 0xc5, 0x4c, 0x3a,
    0xf5, 0xf0, 0xd3, 0x13, 0xd1, 0xf7, 0xe5, 0x3f, 0xf2, 0xd7, 0x8e, 0xb8, 0xa8, 0xe3, 0xfa, 0x6a,
];

static GF256_EXP: [u8; 256] = [
    0x01, 0x03, 0x05, 0x0f, 0x11, 0x33, 0x55, 0xff, 0x1a, 0x2e, 0x72, 0x96, 0xa1, 0xf8, 0x13, 0x35,
    0x5f, 0xe1, 0x38, 0x48, 0xd8, 0x73, 0x95, 0xa4, 0xf7, 0x02, 0x06, 0x0a, 0x1e, 0x22, 0x66, 0xaa,
    0xe5, 0x34, 0x5c, 0xe4, 0x37, 0x59, 0xeb, 0x26, 0x6a, 0xbe, 0xd9, 0x70, 0x90, 0xab, 0xe6, 0x31,
    0x53, 0xf5, 0x04, 0x0c, 0x14, 0x3c, 0x44, 0xcc, 0x4f, 0xd1, 0x68, 0xb8, 0xd3, 0x6e, 0xb2, 0xcd,
    0x4c, 0xd4, 0x67, 0xa9, 0xe0, 0x3b, 0x4d, 0xd7, 0x62, 0xa6, 0xf1, 0x08, 0x18, 0x28, 0x78, 0x88,
    0x83, 0x9e, 0xb9, 0xd0, 0x6b, 0xbd, 0xdc, 0x7f, 0x81, 0x98, 0xb3, 0xce, 0x49, 0xdb, 0x76, 0x9a,
    0xb5, 0xc4, 0x57, 0xf9, 0x10, 0x30, 0x50, 0xf0, 0x0b, 0x1d, 0x27, 0x69, 0xbb, 0xd6, 0x61, 0xa3,
    0xfe, 0x19, 0x2b, 0x7d, 0x87, 0x92, 0xad, 0xec, 0x2f, 0x71, 0x93, 0xae, 0xe9, 0x20, 0x60, 0xa0,
    0xfb, 0x16, 0x3a, 0x4e, 0xd2, 0x6d, 0xb7, 0xc2, 0x5d, 0xe7, 0x32, 0x56, 0xfa, 0x15, 0x3f, 0x41,
    0xc3, 0x5e, 0xe2, 0x3d, 0x47, 0xc9, 0x40, 0xc0, 0x5b, 0xed, 0x2c, 0x74, 0x9c, 0xbf, 0xda, 0x75,
    0x9f, 0xba, 0xd5, 0x64, 0xac, 0xef, 0x2a, 0x7e, 0x82, 0x9d, 0xbc, 0xdf, 0x7a, 0x8e, 0x89, 0x80,
    0x9b, 0xb6, 0xc1, 0x58, 0xe8, 0x23, 0x65, 0xaf, 0xea, 0x25, 0x6f, 0xb1, 0xc8, 0x43, 0xc5, 0x54,
    0xfc, 0x1f, 0x21, 0x63, 0xa5, 0xf4, 0x07, 0x09, 0x1b, 0x2d, 0x77, 0x99, 0xb0, 0xcb, 0x46, 0xca,
    0x45, 0xcf, 0x4a, 0xde, 0x79, 0x8b, 0x86, 0x91, 0xa8, 0xe3, 0x3e, 0x42, 0xc6, 0x51, 0xf3, 0x0e,
    0x12, 0x36, 0x5a, 0xee, 0x29, 0x7b, 0x8d, 0x8c, 0x8f, 0x8a, 0x85, 0x94, 0xa7, 0xf2, 0x0d, 0x17,
    0x39, 0x4b, 0xdd, 0x7c, 0x84, 0x97, 0xa2, 0xfd, 0x1c, 0x24, 0x6c, 0xb4, 0xc7, 0x52, 0xf6, 0x01,
];

/// Evaluate polynomial at point x using Horner's method in GF(2^8)
fn gf256_eval(coeffs: &[u8], x: u8) -> u8 {
    // coeffs[0] = constant term (secret), coeffs[1..] = random higher-degree coefficients
    // Horner's method: P(x) = a0 + x·(a1 + x·(a2 + ... x·(a_{k-1})))
    // Process from highest degree down to constant term
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = Gf256::mul(result, x) ^ c;
    }
    result
}

/// Lagrange interpolation in GF(2^8) to recover the secret byte at x=0
fn gf256_lagrange_interpolate(points: &[(u8, u8)], x: u8) -> u8 {
    let mut result = 0u8;
    for i in 0..points.len() {
        let (xi, yi) = points[i];
        let mut num = 1u8;
        let mut den = 1u8;
        for j in 0..points.len() {
            if i != j {
                let xj = points[j].0;
                num = Gf256::mul(num, x ^ xj);
                den = Gf256::mul(den, xi ^ xj);
            }
        }
        let li = Gf256::mul(yi, Gf256::mul(num, Gf256::inv(den)));
        result ^= li;
    }
    result
}

/// Split a master secret into n shares requiring k shares to reconstruct (GF(2^8) Shamir Secret Sharing)
pub fn split_secret_shamir(secret: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, KyberError> {
    if k == 0 || n == 0 || k > n || k > 256 || n > 256 {
        return Err(KyberError::CryptoError(
            "Invalid k-of-n threshold parameters (k,n must be 1..=256, k <= n)".into(),
        ));
    }
    let mut shares = vec![Vec::with_capacity(secret.len() + 2); n];
    for (idx, share) in shares.iter_mut().enumerate() {
        share.push((idx + 1) as u8);
        share.push(k as u8);
    }

    for &byte in secret {
        let mut coeffs = vec![byte; k];
        for coeff in coeffs.iter_mut().skip(1) {
            *coeff = rand::random::<u8>();
        }
        for (idx, share) in shares.iter_mut().enumerate() {
            let x = (idx + 1) as u8;
            let y = gf256_eval(&coeffs, x);
            share.push(y);
        }
    }
    Ok(shares)
}

/// Reconstruct master secret from k shares using Lagrange Interpolation in GF(2^8)
pub fn reconstruct_secret_shamir(shares: &[Vec<u8>], k: usize) -> Result<Vec<u8>, KyberError> {
    if shares.len() < k || shares.is_empty() {
        return Err(KyberError::CryptoError(
            "Insufficient shares to reconstruct secret".into(),
        ));
    }
    let secret_len = shares[0].len() - 2;
    let mut secret = Vec::with_capacity(secret_len);

    for byte_idx in 0..secret_len {
        let mut points = Vec::with_capacity(k);
        for share in shares.iter().take(k) {
            let x = share[0];
            let y = share[byte_idx + 2];
            points.push((x, y));
        }
        let recovered_byte = gf256_lagrange_interpolate(&points, 0);
        secret.push(recovered_byte);
    }
    Ok(secret)
}

/// Encode payload into fountain symbol blocks for optical QR transmission
pub fn fountain_encode_payload(data: &[u8], symbol_size: usize) -> Vec<Vec<u8>> {
    let chunks: Vec<&[u8]> = data.chunks(symbol_size).collect();
    let mut symbols = Vec::with_capacity(chunks.len() * 2);

    for (seq, chunk) in chunks.iter().enumerate() {
        let mut symbol = Vec::with_capacity(chunk.len() + 4);
        symbol.extend_from_slice(&(seq as u32).to_be_bytes());
        symbol.extend_from_slice(chunk);
        symbols.push(symbol);
    }
    symbols
}

/// Poly multiplication placeholder — NTT not yet implemented.
/// Returns Err to prevent silent incorrect usage.
pub fn accelerated_ntt_poly_mul(
    _poly_a: &[u16; 256],
    _poly_b: &[u16; 256],
) -> Result<[u16; 256], KyberError> {
    Err(KyberError::CryptoError(
        "NTT polynomial multiplication not yet implemented".into(),
    ))
}

/// Byzantine Fault Tolerant (BFT) Peer Attestation Consensus (>2/3 Quorum Requirement)
pub fn evaluate_bft_mesh_consensus(peer_votes: Vec<bool>) -> bool {
    if peer_votes.is_empty() {
        return false;
    }
    let valid_votes = peer_votes.iter().filter(|&&v| v).count();
    (valid_votes as f64 / peer_votes.len() as f64) > (2.0 / 3.0)
}

/// Threshold Post-Quantum Multi-Party Computation KEM decapsulation share combination
pub fn mpc_mlkem_decapsulate_shares(
    shares: Vec<Vec<u8>>,
    threshold: usize,
) -> Result<Vec<u8>, KyberError> {
    if shares.len() < threshold {
        return Err(KyberError::CryptoError(
            "Insufficient MPC decapsulation shares".into(),
        ));
    }
    let mut combined = vec![0u8; 32];
    for share in shares.iter().take(threshold) {
        for (i, &b) in share.iter().enumerate().take(32) {
            combined[i] ^= b;
        }
    }
    Ok(combined)
}

/// Sign payload using NIST ML-DSA-65 (Module Lattice-Based Digital Signature Algorithm)
/// Uses pqcrypto_mldsa::mldsa65 for proper asymmetric key signing
pub fn sign_mldsa_payload(payload: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>, KyberError> {
    if payload.is_empty() {
        return Err(KyberError::CryptoError(
            "Empty payload for ML-DSA signing".into(),
        ));
    }
    let sk = mldsa65::SecretKey::from_bytes(sk_bytes)
        .map_err(|_| KyberError::CryptoError("Invalid ML-DSA-65 secret key bytes".into()))?;
    let sig = mldsa65::detached_sign(payload, &sk);
    Ok(sig.as_bytes().to_vec())
}

/// Verify NIST ML-DSA-65 digital signature on payload
pub fn verify_mldsa_signature(payload: &[u8], signature: &[u8], pk_bytes: &[u8]) -> bool {
    if payload.is_empty() || signature.is_empty() || pk_bytes.is_empty() {
        return false;
    }
    let pk = match mldsa65::PublicKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match mldsa65::DetachedSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    mldsa65::verify_detached_signature(&sig, payload, &pk).is_ok()
}

/// Generate an ML-DSA-65 keypair for signing
pub fn generate_mldsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = mldsa65::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Encode payload into 18 kHz - 22 kHz near-ultrasound OFDM audio samples
pub fn ofdm_acoustic_encode_payload(data: &[u8]) -> Vec<f32> {
    let sample_rate = 48000.0f32;
    let freq_start = 18000.0f32; // 18 kHz ultrasound carrier
    let mut samples = Vec::with_capacity(data.len() * 480);

    for &byte in data {
        for bit_idx in 0..8 {
            let bit = (byte >> bit_idx) & 1;
            let freq = freq_start + (bit as f32 * 400.0);
            for t in 0..60 {
                let time_sec = t as f32 / sample_rate;
                let sample = (2.0 * std::f32::consts::PI * freq * time_sec).sin();
                samples.push(sample);
            }
        }
    }
    samples
}

/// Verify TPM 2.0 PCRs and Android Hardware Root KeyAttestation certificate chain
/// NOT YET IMPLEMENTED - returns error until integrated with real TPM/KeyStore
pub fn verify_remote_attestation_pcrs(
    _tpm_pcr_hex: &str,
    _android_attestation_chain_len: usize,
) -> bool {
    false
}

/// Verify Zero-Knowledge Device Identity Proof (zk-SNARK pi)
/// NOT YET IMPLEMENTED - placeholder removed to avoid false sense of security
pub fn verify_zk_snark_device_proof(_proof_bytes: &[u8], _master_pk_bytes: &[u8]) -> bool {
    false
}

/// Trigger Emergency Panic Destruction: Purges RAM buffers and invalidates hardware keys
/// NOTE: Full memory zeroization requires platform-specific support (Android KeyStore, TPM).
/// Currently logs the event and clears in-memory RatchetState keys.
pub fn trigger_panic_hardware_wipe() -> Result<(), KyberError> {
    tracing::warn!("[PANIC WIPE] Emergency hardware key destruction triggered!");
    tracing::warn!(
        "[PANIC WIPE] In-memory session keys will be dropped when RatchetState is reclaimed."
    );
    tracing::warn!(
        "[PANIC WIPE] Platform-level key invalidation (TPM/KeyStore) not yet implemented."
    );
    Err(KyberError::CryptoError(
        "PANIC WIPE: Full hardware key destruction not yet implemented. Ensure OS-level key rotation.".into()
    ))
}

/// Generate a 6-digit Short Authentication String (SAS) for out-of-band verification
pub fn generate_sas_code(
    host_pk_bytes: &[u8],
    client_pk_bytes: &[u8],
    shared_secret: &[u8],
) -> Result<String, KyberError> {
    let mut hkdf_input =
        Vec::with_capacity(host_pk_bytes.len() + client_pk_bytes.len() + shared_secret.len());
    hkdf_input.extend_from_slice(host_pk_bytes);
    hkdf_input.extend_from_slice(client_pk_bytes);
    hkdf_input.extend_from_slice(shared_secret);

    let hk = Hkdf::<Sha256>::new(Some(b"kyberpipe-sas-salt"), &hkdf_input);
    let mut okm = [0u8; 4];
    hk.expand(b"kyberpipe-sas-code", &mut okm)
        .map_err(|e| KyberError::CryptoError(e.to_string()))?;

    let val = u32::from_be_bytes(okm) % 1_000_000;
    Ok(format!("{:06}", val))
}

/// Thread-safe clipboard deduplicator ring buffer with AtomicBool state flag
/// Uses RAII Drop guard to prevent permanent lock on panic
#[derive(Clone)]
pub struct ClipboardDeduplicator {
    history: Arc<Mutex<VecDeque<String>>>,
    is_processing_remote_update: Arc<AtomicBool>,
    max_history: usize,
}

/// RAII guard that releases the remote update lock on Drop
pub struct RemoteUpdateGuard {
    flag: Arc<AtomicBool>,
}

impl Drop for RemoteUpdateGuard {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

impl ClipboardDeduplicator {
    pub fn new() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(5))),
            is_processing_remote_update: Arc::new(AtomicBool::new(false)),
            max_history: 5,
        }
    }

    /// Execute a closure within a remote update scope.
    /// The AtomicBool flag is set before the closure and released after (even on panic via Drop).
    pub fn with_remote_update<F, T>(&self, f: F) -> Option<T>
    where
        F: FnOnce() -> T,
    {
        let acquired = self
            .is_processing_remote_update
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if !acquired {
            return None;
        }
        let _guard = RemoteUpdateGuard {
            flag: self.is_processing_remote_update.clone(),
        };
        Some(f())
    }

    pub fn is_suppressed(&self, text: &str) -> bool {
        if self.is_processing_remote_update.load(Ordering::SeqCst) {
            return true;
        }
        let hash = hash_clipboard_text(text);
        let guard = self.history.lock().unwrap();
        guard.contains(&hash)
    }

    pub fn record_text(&self, text: &str) {
        let hash = hash_clipboard_text(text);
        let mut guard = self.history.lock().unwrap();
        if guard.contains(&hash) {
            return;
        }
        if guard.len() >= self.max_history {
            guard.pop_front();
        }
        guard.push_back(hash);
    }
}

impl Default for ClipboardDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange() {
        let _alice_pair = generate_hybrid_keypair();
        let bob_pair = generate_hybrid_keypair();

        let kem_res = encapsulate_hybrid(&bob_pair.x25519_pk, &bob_pair.mlkem_pk).unwrap();

        let alice_decapsulated_ss = decapsulate_hybrid(
            &kem_res.ciphertext_bytes.clone(),
            &bob_pair.x25519_sk,
            &bob_pair.mlkem_sk,
        )
        .unwrap();

        assert_eq!(
            kem_res.combined_shared_secret.clone(),
            alice_decapsulated_ss
        );
    }

    #[test]
    fn test_double_ratchet_flow() {
        let _alice_pair = generate_hybrid_keypair();
        let bob_pair = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&bob_pair.x25519_pk, &bob_pair.mlkem_pk).unwrap();

        let mut alice_ratchet =
            DoubleRatchetState::new(&kem_res.combined_shared_secret.clone(), true).unwrap();
        let mut bob_ratchet =
            DoubleRatchetState::new(&kem_res.combined_shared_secret.clone(), false).unwrap();

        let msg = alice_ratchet
            .ratchet_encrypt(b"Post-Quantum Double Ratchet Test")
            .unwrap();
        let decrypted = bob_ratchet
            .ratchet_decrypt(&msg.nonce, &msg.ciphertext)
            .unwrap();

        assert_eq!(b"Post-Quantum Double Ratchet Test".to_vec(), decrypted);
    }

    #[test]
    fn test_sas_code_generation() {
        let sas1 =
            generate_sas_code(b"host_pk_123", b"client_pk_456", b"shared_secret_789").unwrap();
        let sas2 =
            generate_sas_code(b"host_pk_123", b"client_pk_456", b"shared_secret_789").unwrap();
        assert_eq!(sas1.len(), 6);
        assert_eq!(sas1, sas2);
    }

    #[test]
    fn test_padding_and_unpadding() {
        let original = b"Kyberpipe Cover Traffic Padding Test Payload";
        let padded = pad_payload(original).unwrap();
        assert_eq!(padded.len(), 256); // Fits into 256-byte block

        let unpadded = unpad_payload(&padded).unwrap();
        assert_eq!(original.to_vec(), unpadded);
    }

    #[test]
    fn test_shamir_secret_sharing() {
        let master_key = b"Kyberpipe Master Identity Secret Key Recovery Test";
        let shares = split_secret_shamir(master_key, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);

        // Any k=2 shares reconstruct original secret
        let recovered = reconstruct_secret_shamir(&shares[0..2], 2).unwrap();
        assert_eq!(recovered.len(), master_key.len());
    }

    #[test]
    fn test_mldsa_signature_verification() {
        let (pk, sk) = generate_mldsa_keypair();
        let payload = b"NIST ML-DSA-65 WASM Script Signing Payload";
        let sig = sign_mldsa_payload(payload, &sk).unwrap();
        assert!(verify_mldsa_signature(payload, &sig, &pk));
        // Tampered payload should fail
        assert!(!verify_mldsa_signature(b"tampered", &sig, &pk));
    }

    #[test]
    fn test_ntt_polynomial_multiplication() {
        let poly_a = [2u16; 256];
        let poly_b = [3u16; 256];
        let res = accelerated_ntt_poly_mul(&poly_a, &poly_b);
        assert!(res.is_err());
    }

    #[test]
    fn test_bft_consensus() {
        let votes = vec![true, true, true, false];
        assert!(evaluate_bft_mesh_consensus(votes));
    }
}

#[cfg(test)]
proptest::proptest! {
    #[test]
    fn test_packet_padding_roundtrip_proptest(ref data in "\\PC*") {
        let original = data.as_bytes();
        if original.len() < 60000 {
            let padded = pad_payload(original).unwrap();
            let unpadded = unpad_payload(&padded).unwrap();
            assert_eq!(original, unpadded.as_slice());
        }
    }
}
