//! Key Management, KEM, Session Keys, and Encryption API.
//!
//! Domain module grouping post-quantum key generation, hybrid KEM,
//! session key derivation, and AEAD encryption/decryption functions.

use crate::error::KyberError;
use crate::{crypto, ensure_panic_hook_installed, session_handle, EncryptedPayload, PqKeyPair, PqKeyPairRaw, PqKemResponse};
use zeroize::Zeroize;

// ── Hybrid Key Generation ──

#[uniffi::export]
pub fn initialize_pq_handshake() -> Result<(), KyberError> {
    ensure_panic_hook_installed();
    let _pair = crypto::generate_hybrid_keypair();
    Ok(())
}

#[uniffi::export]
pub fn trigger_panic_hardware_wipe() -> Result<(), KyberError> {
    ensure_panic_hook_installed();
    // Real zeroization: clear every ratchet session (chain keys, root keys,
    // keypairs), destroy every session-key handle, and invalidate in-flight
    // operations via the destruct generation counter.
    crate::ratchet_ffi::ratchet_clear_all_sessions_impl();
    crate::session_handle::session_key_destroy_all();
    crate::increment_destruct_generation();
    Ok(())
}

#[uniffi::export]
pub fn generate_pq_keypair() -> Result<PqKeyPair, KyberError> {
    ensure_panic_hook_installed();
    let pair = crypto::generate_hybrid_keypair();
    Ok(PqKeyPair {
        x25519_pk: pair.x25519_pk.to_vec(),
        x25519_sk: pair.x25519_sk.to_vec(),
        mlkem_pk: pair.mlkem_pk.clone(),
        mlkem_sk: pair.mlkem_sk.clone(),
    })
}

#[uniffi::export]
pub fn generate_pq_keypair_raw() -> Result<PqKeyPairRaw, KyberError> {
    ensure_panic_hook_installed();
    let pair = crypto::generate_hybrid_keypair();
    Ok(PqKeyPairRaw {
        x25519_pk: pair.x25519_pk.to_vec(),
        x25519_sk: pair.x25519_sk.to_vec(),
        mlkem_pk: pair.mlkem_pk.clone(),
        mlkem_sk: pair.mlkem_sk.clone(),
    })
}

// ── Hybrid KEM ──

#[uniffi::export]
pub fn encapsulate_pq_secret(
    peer_x25519_pk: Vec<u8>,
    peer_mlkem_pk: Vec<u8>,
) -> Result<PqKemResponse, KyberError> {
    ensure_panic_hook_installed();
    if peer_x25519_pk.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: peer_x25519_pk.len() as u64,
        });
    }
    let mut x25519_arr = [0u8; 32];
    x25519_arr.copy_from_slice(&peer_x25519_pk);
    if peer_mlkem_pk.len() != 1184 {
        return Err(KyberError::InvalidKeyLength {
            expected: 1184,
            got: peer_mlkem_pk.len() as u64,
        });
    }
    let res = crypto::encapsulate_hybrid(&x25519_arr, &peer_mlkem_pk)?;
    Ok(PqKemResponse {
        ciphertext: res.ciphertext_bytes.clone(),
        shared_secret: res.combined_shared_secret.clone(),
    })
}

#[uniffi::export]
pub fn decapsulate_pq_secret(
    ciphertext: Vec<u8>,
    my_x25519_sk: Vec<u8>,
    my_mlkem_sk: Vec<u8>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    if my_x25519_sk.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: my_x25519_sk.len() as u64,
        });
    }
    let mut x25519_sk_arr = [0u8; 32];
    x25519_sk_arr.copy_from_slice(&my_x25519_sk);
    let mut my_x25519_sk = my_x25519_sk;
    my_x25519_sk.zeroize();
    if my_mlkem_sk.len() != 2400 {
        return Err(KyberError::InvalidKeyLength {
            expected: 2400,
            got: my_mlkem_sk.len() as u64,
        });
    }
    let result = crypto::decapsulate_hybrid(&ciphertext, &x25519_sk_arr, &my_mlkem_sk);
    let mut my_mlkem_sk = my_mlkem_sk;
    my_mlkem_sk.zeroize();
    result
}

// ── Session Key Derivation ──

#[uniffi::export]
pub fn derive_session_key(shared_secret: Vec<u8>, salt: Vec<u8>) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    let derived = crypto::derive_session_key(&shared_secret, &salt, b"kyberpipe-hybrid-session")?;
    Ok(derived.to_vec())
}

/// The canonical domain-separation salt bytes for `derive_session_key`.
/// Exported through UniFFI so Android consumes the SAME bytes as the desktop —
/// the single source of truth for the session-key derivation salt. Never
/// re-encode this as hex/ASCII at a call site (audit finding #2).
#[uniffi::export]
pub fn session_derivation_salt() -> Vec<u8> {
    ensure_panic_hook_installed();
    crate::crypto::SESSION_KEY_DERIVATION_SALT.to_vec()
}

// ── Session Key Handle API ──
// Raw key bytes never cross the FFI boundary.

#[uniffi::export]
pub fn session_key_create(key_bytes: Vec<u8>) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    session_handle::session_key_create(key_bytes)
}

#[uniffi::export]
pub fn session_key_destroy(handle: u64) {
    ensure_panic_hook_installed();
    session_handle::session_key_destroy(handle)
}

/// Destroy EVERY live session key handle, zeroizing all key bytes. Used by the
/// panic self-destruct path so no handle (not just the desktop's) survives with
/// its key material in memory (audit finding #16).
#[uniffi::export]
pub fn session_key_destroy_all() {
    ensure_panic_hook_installed();
    session_handle::session_key_destroy_all()
}

#[uniffi::export]
pub fn session_key_encrypt(handle: u64, data: Vec<u8>) -> Result<EncryptedPayload, KyberError> {
    ensure_panic_hook_installed();
    let (nonce, ciphertext) = session_handle::session_key_encrypt(handle, &data)?;
    Ok(EncryptedPayload { nonce, ciphertext })
}

#[uniffi::export]
pub fn session_key_decrypt(
    handle: u64,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    session_handle::session_key_decrypt(handle, &nonce, &ciphertext)
}

#[uniffi::export]
pub fn session_key_hash(handle: u64) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    session_handle::session_key_hash(handle)
}

// ── Deprecated Key-Byte API ──
// Use session_key_* with opaque handles instead.

#[uniffi::export]
pub fn encrypt_payload_with_handle(
    session_key: Vec<u8>,
    data: Vec<u8>,
) -> Result<EncryptedPayload, KyberError> {
    ensure_panic_hook_installed();
    if session_key.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: session_key.len() as u64,
        });
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&session_key);

    // Fresh random 96-bit nonce. The previous scheme derived a deterministic
    // sid from the key and used a process-global counter that restarted at 1 on
    // every process launch, so two processes (or a restart) could encrypt the
    // same message under the same (key, nonce) — keystream reuse.
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

    let ciphertext = crypto::encrypt_chacha20(&key_arr, &nonce_bytes, &data, &[])?;
    Ok(EncryptedPayload {
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

#[uniffi::export]
pub fn decrypt_payload_with_handle(
    session_key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, KyberError> {
    ensure_panic_hook_installed();
    if session_key.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: session_key.len() as u64,
        });
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&session_key);

    if nonce.len() != 12 {
        return Err(KyberError::DecryptionFailed(
            "Nonce must be 12 bytes".into(),
        ));
    }
    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce);

    crypto::decrypt_chacha20(&key_arr, &nonce_arr, &ciphertext, &[])
}

// ── Utility ──

pub fn is_duplicate_clipboard(content_hash: String, recent_hashes: Vec<String>) -> bool {
    recent_hashes.contains(&content_hash)
}

#[uniffi::export]
pub fn compute_sha256(data: Vec<u8>) -> String {
    ensure_panic_hook_installed();
    // Hash the RAW bytes. The previous implementation converted to a lossy
    // UTF-8 String first, so invalid bytes were replaced with U+FFFD and two
    // distinct binary payloads could hash identically (dedup suppression
    // silently dropped valid remote content).
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&data);
    hex::encode(hasher.finalize())
}
