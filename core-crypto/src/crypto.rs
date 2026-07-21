use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use crate::error::KyberError;

pub const CHUNKS_SIZE: usize = 64 * 1024; // 64 KB per block chunk

/// Holds raw Hybrid (X25519 + ML-KEM-768) keypair
#[derive(Clone, Debug)]
pub struct HybridKeyPair {
    pub x25519_pk: [u8; 32],
    pub x25519_sk: [u8; 32],
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

/// Holds Hybrid encapsulation response
pub struct HybridKemResult {
    pub ciphertext_bytes: Vec<u8>,
    pub combined_shared_secret: Vec<u8>,
}

/// Post-Quantum Ephemeral Double Ratchet State (Signal PQXDH-inspired)
pub struct DoubleRatchetState {
    pub root_key: [u8; 32],
    pub sending_chain_key: [u8; 32],
    pub receiving_chain_key: [u8; 32],
    pub send_message_count: u64,
    pub recv_message_count: u64,
    pub our_hybrid_pair: HybridKeyPair,
    pub peer_x25519_pk: Option<[u8; 32]>,
    pub peer_mlkem_pk: Option<Vec<u8>>,
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
        })
    }

    /// Advance sending symmetric chain key and encrypt plaintext payload
    pub fn ratchet_encrypt(&mut self, plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>), KyberError> {
        // Advance chain key: K_{i+1} = HMAC-SHA256(K_i, "message-key")
        let hk = Hkdf::<Sha256>::new(Some(&self.sending_chain_key), b"step");
        let mut msg_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-send-chain", &mut self.sending_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        let nonce = generate_nonce_from_seq(self.send_message_count);
        self.send_message_count += 1;

        let ciphertext = encrypt_chacha20(&msg_key, &nonce, plaintext)?;
        Ok((nonce, ciphertext))
    }

    /// Advance receiving symmetric chain key and decrypt ciphertext payload
    pub fn ratchet_decrypt(&mut self, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, KyberError> {
        let hk = Hkdf::<Sha256>::new(Some(&self.receiving_chain_key), b"step");
        let mut msg_key = [0u8; 32];
        hk.expand(b"kyberpipe-msg-key", &mut msg_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-next-recv-chain", &mut self.receiving_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        self.recv_message_count += 1;
        decrypt_chacha20(&msg_key, nonce, ciphertext)
    }

    /// Perform a Post-Quantum Ephemeral DH/KEM Ratchet re-key step
    pub fn dh_ratchet_rekey(&mut self, peer_x25519_pk: [u8; 32], peer_mlkem_pk: &[u8]) -> Result<HybridKemResult, KyberError> {
        let kem_res = encapsulate_hybrid(&peer_x25519_pk, peer_mlkem_pk)?;
        
        let hk = Hkdf::<Sha256>::new(Some(&self.root_key), &kem_res.combined_shared_secret);
        hk.expand(b"kyberpipe-next-root-key", &mut self.root_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-send-chain", &mut self.sending_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;
        hk.expand(b"kyberpipe-recv-chain", &mut self.receiving_chain_key)
            .map_err(|e| KyberError::CryptoError(e.to_string()))?;

        self.peer_x25519_pk = Some(peer_x25519_pk);
        self.peer_mlkem_pk = Some(peer_mlkem_pk.to_vec());
        self.our_hybrid_pair = generate_hybrid_keypair();

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

/// Generate a 6-digit Short Authentication String (SAS) for out-of-band verification
pub fn generate_sas_code(
    host_pk_bytes: &[u8],
    client_pk_bytes: &[u8],
    shared_secret: &[u8],
) -> Result<String, KyberError> {
    let mut hkdf_input = Vec::with_capacity(host_pk_bytes.len() + client_pk_bytes.len() + shared_secret.len());
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
#[derive(Clone)]
pub struct ClipboardDeduplicator {
    history: Arc<Mutex<VecDeque<String>>>,
    is_processing_remote_update: Arc<AtomicBool>,
    max_history: usize,
}

impl ClipboardDeduplicator {
    pub fn new() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(5))),
            is_processing_remote_update: Arc::new(AtomicBool::new(false)),
            max_history: 5,
        }
    }

    pub fn begin_remote_update(&self) -> bool {
        self.is_processing_remote_update
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    pub fn end_remote_update(&self) {
        self.is_processing_remote_update.store(false, Ordering::SeqCst);
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
            &kem_res.ciphertext_bytes,
            &bob_pair.x25519_sk,
            &bob_pair.mlkem_sk,
        )
        .unwrap();

        assert_eq!(kem_res.combined_shared_secret, alice_decapsulated_ss);
    }

    #[test]
    fn test_double_ratchet_flow() {
        let _alice_pair = generate_hybrid_keypair();
        let bob_pair = generate_hybrid_keypair();
        let kem_res = encapsulate_hybrid(&bob_pair.x25519_pk, &bob_pair.mlkem_pk).unwrap();

        let mut alice_ratchet = DoubleRatchetState::new(&kem_res.combined_shared_secret, true).unwrap();
        let mut bob_ratchet = DoubleRatchetState::new(&kem_res.combined_shared_secret, false).unwrap();

        let (nonce, ciphertext) = alice_ratchet.ratchet_encrypt(b"Post-Quantum Double Ratchet Test").unwrap();
        let decrypted = bob_ratchet.ratchet_decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(b"Post-Quantum Double Ratchet Test".to_vec(), decrypted);
    }

    #[test]
    fn test_sas_code_generation() {
        let sas1 = generate_sas_code(b"host_pk_123", b"client_pk_456", b"shared_secret_789").unwrap();
        let sas2 = generate_sas_code(b"host_pk_123", b"client_pk_456", b"shared_secret_789").unwrap();
        assert_eq!(sas1.len(), 6);
        assert_eq!(sas1, sas2);
    }
}
