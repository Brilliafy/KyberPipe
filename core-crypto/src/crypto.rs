use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _};
use sha2::Sha256;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use crate::error::KyberError;

pub const CHUNKS_SIZE: usize = 64 * 1024; // 64 KB per block chunk

/// Holds raw ML-KEM-768 keypair
pub struct PqKeyPair {
    pub public_key_bytes: Vec<u8>,
    pub secret_key_bytes: Vec<u8>,
}

/// Holds ML-KEM-768 encapsulation result
pub struct PqKemResult {
    pub ciphertext_bytes: Vec<u8>,
    pub shared_secret_bytes: Vec<u8>,
}

/// Generate a NIST FIPS 203 ML-KEM-768 keypair.
pub fn generate_kyber_keypair() -> PqKeyPair {
    let (pk, sk) = kyber768::keypair();
    PqKeyPair {
        public_key_bytes: pk.as_bytes().to_vec(),
        secret_key_bytes: sk.as_bytes().to_vec(),
    }
}

/// Encapsulate a shared secret against the target peer's ML-KEM-768 public key.
pub fn encapsulate_kyber(public_key_bytes: &[u8]) -> Result<PqKemResult, KyberError> {
    let pk = kyber768::PublicKey::from_bytes(public_key_bytes).map_err(|_| {
        KyberError::EncapsulationFailed("Invalid ML-KEM-768 public key bytes".into())
    })?;
    let (ss, ct) = kyber768::encapsulate(&pk);
    Ok(PqKemResult {
        ciphertext_bytes: ct.as_bytes().to_vec(),
        shared_secret_bytes: ss.as_bytes().to_vec(),
    })
}

/// Decapsulate the ciphertext using the recipient's ML-KEM-768 secret key.
pub fn decapsulate_kyber(
    ciphertext_bytes: &[u8],
    secret_key_bytes: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let ct = kyber768::Ciphertext::from_bytes(ciphertext_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 ciphertext bytes".into())
    })?;
    let sk = kyber768::SecretKey::from_bytes(secret_key_bytes).map_err(|_| {
        KyberError::DecapsulationFailed("Invalid ML-KEM-768 secret key bytes".into())
    })?;
    let ss = kyber768::decapsulate(&ct, &sk);
    Ok(ss.as_bytes().to_vec())
}

/// Derive a 256-bit (32-byte) symmetric key using HKDF-SHA256 from the shared secret.
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

/// Thread-safe clipboard deduplicator ring buffer holding the last 3 synchronized SHA-256 hashes
#[derive(Clone)]
pub struct ClipboardDeduplicator {
    history: Arc<Mutex<VecDeque<String>>>,
    max_history: usize,
}

impl ClipboardDeduplicator {
    pub fn new() -> Self {
        Self {
            history: Arc::new(Mutex::new(VecDeque::with_capacity(3))),
            max_history: 3,
        }
    }

    /// Returns true if the hash is already present in the recent history (duplicate)
    pub fn is_duplicate(&self, hash: &str) -> bool {
        let guard = self.history.lock().unwrap();
        guard.contains(&hash.to_string())
    }

    /// Records a new hash into the rolling history
    pub fn record_hash(&self, hash: String) {
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
    fn test_crypto_operations() {
        let pair = generate_kyber_keypair();
        assert_eq!(pair.public_key_bytes.len(), kyber768::public_key_bytes());
        assert_eq!(pair.secret_key_bytes.len(), kyber768::secret_key_bytes());

        let res = encapsulate_kyber(&pair.public_key_bytes).unwrap();
        assert_eq!(res.ciphertext_bytes.len(), kyber768::ciphertext_bytes());

        let decapsulated = decapsulate_kyber(&res.ciphertext_bytes, &pair.secret_key_bytes).unwrap();
        assert_eq!(res.shared_secret_bytes, decapsulated);
    }
}

