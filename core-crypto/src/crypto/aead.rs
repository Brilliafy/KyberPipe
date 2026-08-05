use crate::error::KyberError;
use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit},
    ChaCha20Poly1305, Nonce,
};

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

/// Generate a 96-bit nonce from a 64-bit sequence counter and a domain/generation identifier.
///
/// Wire layout (fixed, cross-platform — do NOT change without a protocol
/// version bump):
///   bytes 0..=3  — the `sid_or_generation` value as big-endian u32. Callers
///                  pass the RATCHET GENERATION, giving each rekey generation
///                  its own nonce sub-domain.
///   bytes 4..=11 — the monotonically increasing message counter as big-endian
///                  u64.
///
/// AUDIT F12 FIX: the previous doc claimed bytes 0-3 encode "a per-key session
/// ID (derived from the session key via HKDF) combined with the generation
/// number via wrapping addition" — the implementation never did that, and both
/// the sync path (`sync.rs`) and the decrypt path (`decrypt.rs`) parse these
/// bytes back as the raw generation. The doc now matches the implementation.
/// Nonce uniqueness is still guaranteed within a session: a fresh session
/// (re-pair) derives a NEW key, and within one key the (generation, seq) pair
/// is unique because a generation is bumped only on a committed rekey that
/// resets both counters — so (key, generation, seq) is never repeated.
pub fn generate_nonce_from_seq(seq: u64, sid_or_generation: u32) -> [u8; 12] {
    // AUDIT P4-3: the bound must hold in RELEASE builds too — the debug_assert
    // compiles out, so any future call site passing an out-of-domain generation
    // would silently collide with the reserved domain. Clamp the generation to
    // `u32::MAX - 1` (a domain no legitimate generation can occupy, since the
    // ratchet refuses to encrypt at `u32::MAX`) and surface the violation
    // loudly instead of emitting a nonce whose generation prefix could collide.
    let generation = if sid_or_generation == u32::MAX {
        tracing::error!(
            "Nonce generation {} is out of the valid domain (< u32::MAX) — clamping to {}; nonce domain separation otherwise compromised",
            sid_or_generation,
            u32::MAX - 1
        );
        debug_assert!(
            false,
            "Ratchet generation {sid_or_generation} exceeds u32::MAX — nonce domain separation compromised"
        );
        u32::MAX - 1
    } else {
        sid_or_generation
    };
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&generation.to_be_bytes());
    let seq_bytes = seq.to_be_bytes();
    nonce[4..12].copy_from_slice(&seq_bytes);
    nonce
}
