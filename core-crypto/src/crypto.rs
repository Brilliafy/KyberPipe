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
pub struct HybridKeyPair {
    pub x25519_pk: [u8; 32],
    pub x25519_sk: [u8; 32],
    pub mlkem_pk: Vec<u8>,
    pub mlkem_sk: Vec<u8>,
}

/// Holds Hybrid encapsulation response
pub struct HybridKemResult {
    pub ciphertext_bytes: Vec<u8>, // Contains ephem X25519 PK (32 bytes) + ML-KEM CT (1088 bytes)
    pub combined_shared_secret: Vec<u8>, // Derived from X25519 SS + ML-KEM SS
}

/// Generate Hybrid (X25519 + NIST ML-KEM-768) keypair.
pub fn generate_hybrid_keypair() -> HybridKeyPair {
    // Generate classical ECC X25519 keypair
    let mut rng = rand::thread_rng();
    let x25519_sk = X25519StaticSecret::random_from_rng(&mut rng);
    let x25519_pk = X25519PublicKey::from(&x25519_sk);

    // Generate NIST PQC ML-KEM-768 keypair
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
    // 1. Classical X25519 ephemeral key exchange
    let mut rng = rand::thread_rng();
    let ephem_x25519_sk = X25519StaticSecret::random_from_rng(&mut rng);
    let ephem_x25519_pk = X25519PublicKey::from(&ephem_x25519_sk);
    let peer_x25519_pk = X25519PublicKey::from(*peer_x25519_pk_bytes);
    let x25519_ss = ephem_x25519_sk.diffie_hellman(&peer_x25519_pk);

    // 2. Post-Quantum ML-KEM-768 encapsulation
    let peer_mlkem_pk = kyber768::PublicKey::from_bytes(peer_mlkem_pk_bytes).map_err(|_| {
        KyberError::EncapsulationFailed("Invalid ML-KEM-768 public key bytes".into())
    })?;
    let (mlkem_ss, mlkem_ct) = kyber768::encapsulate(&peer_mlkem_pk);

    // 3. Combine both shared secrets: X25519 SS || ML-KEM SS
    let mut combined_ss = Vec::with_capacity(32 + mlkem_ss.as_bytes().len());
    combined_ss.extend_from_slice(x25519_ss.as_bytes());
    combined_ss.extend_from_slice(mlkem_ss.as_bytes());

    // 4. Pack combined ciphertext: Ephemeral X25519 PK (32 bytes) || ML-KEM CT (1088 bytes)
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

    // 1. Split ciphertext into Ephemeral X25519 PK (32 bytes) and ML-KEM CT
    let (ephem_x25519_pk_bytes, mlkem_ct_bytes) = combined_ct_bytes.split_at(32);
    let mut ephem_x25519_arr = [0u8; 32];
    ephem_x25519_arr.copy_from_slice(ephem_x25519_pk_bytes);
    let ephem_x25519_pk = X25519PublicKey::from(ephem_x25519_arr);

    // 2. Derive classical X25519 shared secret
    let my_x25519_sk = X25519StaticSecret::from(*my_x25519_sk_bytes);
    let x25519_ss = my_x25519_sk.diffie_hellman(&ephem_x25519_pk);

    // 3. Decapsulate ML-KEM-768 shared secret
    let mlkem_ct = kyber768::Ciphertext::from_bytes(mlkem_ct_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 ciphertext bytes".into())
    })?;
    let my_mlkem_sk = kyber768::SecretKey::from_bytes(my_mlkem_sk_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 secret key bytes".into())
    })?;
    let mlkem_ss = kyber768::decapsulate(&mlkem_ct, &my_mlkem_sk);

    // 4. Combine shared secrets
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

    /// Sets the state flag before applying a remote clipboard update to suppress self-triggered local events
    pub fn begin_remote_update(&self) -> bool {
        self.is_processing_remote_update
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Resets the remote update state flag
    pub fn end_remote_update(&self) {
        self.is_processing_remote_update.store(false, Ordering::SeqCst);
    }

    /// Returns true if currently processing a remote update or if text hash is in recent history
    pub fn is_suppressed(&self, text: &str) -> bool {
        if self.is_processing_remote_update.load(Ordering::SeqCst) {
            return true;
        }
        let hash = hash_clipboard_text(text);
        let guard = self.history.lock().unwrap();
        guard.contains(&hash)
    }

    /// Records a new normalized text hash into the rolling history
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
    fn test_clipboard_deduplication_and_normalization() {
        let dedup = ClipboardDeduplicator::new();
        let text1 = "Hello World\r\nKyberpipe Clipboard";
        let text1_normalized = "Hello World\nKyberpipe Clipboard";

        dedup.record_text(text1);
        assert!(dedup.is_suppressed(text1_normalized));

        // Test remote update suppression flag
        assert!(dedup.begin_remote_update());
        assert!(dedup.is_suppressed("Brand New Clipboard Text"));
        dedup.end_remote_update();
        assert!(!dedup.is_suppressed("Brand New Clipboard Text"));
    }
}
