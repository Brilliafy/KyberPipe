use crate::error::KyberError;
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use std::sync::OnceLock;

/// Encrypt payload data with ChaCha20-Poly1305 AEAD and optional AAD.
/// When aad is provided (e.g., rekey parameters), it is bound into the
/// authentication tag — preventing an attacker from swapping rekey data
/// while reusing a valid ciphertext.
pub fn encrypt_chacha20(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_arr = Nonce::from_slice(nonce);
    if aad.is_empty() {
        // Optimized path without AAD — matches old API for backward compat
        cipher.encrypt(nonce_arr, plaintext).map_err(|e| {
            KyberError::EncryptionFailed(format!("ChaCha20Poly1305 encrypt error: {e}"))
        })
    } else {
        let mut buf = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce_arr, aad, &mut buf)
            .map_err(|e| {
                KyberError::EncryptionFailed(format!("ChaCha20Poly1305 encrypt error: {e}"))
            })?;
        buf.extend_from_slice(&tag);
        Ok(buf)
    }
}

/// Decrypt payload data with ChaCha20-Poly1305 AEAD with optional AAD.
/// The AAD must match what was used during encryption for verification to succeed.
pub fn decrypt_chacha20(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, KyberError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_arr = Nonce::from_slice(nonce);
    if aad.is_empty() {
        // Optimized path without AAD — matches old API for backward compat
        cipher.decrypt(nonce_arr, ciphertext).map_err(|e| {
            KyberError::DecryptionFailed(format!("ChaCha20Poly1305 decrypt error: {e}"))
        })
    } else {
        if ciphertext.len() < 16 {
            return Err(KyberError::DecryptionFailed("Ciphertext too short".into()));
        }
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let mut buf = ct.to_vec();
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        cipher
            .decrypt_in_place_detached(nonce_arr, aad, &mut buf, &tag_arr.into())
            .map_err(|e| {
                KyberError::DecryptionFailed(format!("ChaCha20Poly1305 decrypt error: {e}"))
            })?;
        Ok(buf)
    }
}

/// Generate a 96-bit nonce from a 64-bit sequence counter.
/// Bytes 0-3 encode a random per-process session identifier to prevent
/// key+nonce reuse across process restarts. Bytes 4-11 encode the counter.
pub fn generate_nonce_from_seq(seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&nonce_session_id().to_be_bytes());
    let seq_bytes = seq.to_be_bytes();
    nonce[4..12].copy_from_slice(&seq_bytes);
    nonce
}

fn nonce_session_id() -> u32 {
    static SID: OnceLock<u32> = OnceLock::new();
    *SID.get_or_init(rand::random)
}
