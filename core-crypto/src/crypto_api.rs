//! Key Management, KEM, Session Keys, and Encryption API.
//!
//! Domain module grouping post-quantum key generation, hybrid KEM,
//! session key derivation, and AEAD encryption/decryption functions.

use crate::error::KyberError;
use crate::{
    crypto, ensure_panic_hook_installed, kem_handle, session_handle, EncryptedPayload,
    PqKemHandleResponse, PqKemResponse, PqKeyPair, PqPairingPublic,
};
use pqcrypto_kyber::kyber768;
use zeroize::Zeroize;

// ── ML-KEM-768 size constants (audit finding #12) ──
// Derived from the pqcrypto_traits constants instead of hard-coded literals so
// a kyber version bump (or an ML-KEM-1024 switch) cannot silently break the
// UniFFI boundary with stale lengths. Exported through `kem_sizes` for
// cross-platform introspection.

/// Size of an ML-KEM-768 public key (1184 bytes).
pub const MLKEM768_PUBLIC_KEY_BYTES: usize = kyber768::public_key_bytes();
/// Size of an ML-KEM-768 secret key (2400 bytes).
pub const MLKEM768_SECRET_KEY_BYTES: usize = kyber768::secret_key_bytes();
/// Size of an ML-KEM-768 ciphertext (1088 bytes).
pub const MLKEM768_CIPHERTEXT_BYTES: usize = kyber768::ciphertext_bytes();

/// Introspect the ML-KEM-768 sizes the FFI contract is built on. Exported so
/// Android and the desktop can assert their expectations at startup instead of
/// failing at runtime with INVALID_KEY_LENGTH after a dependency upgrade
/// (audit finding #12).
#[uniffi::export]
pub fn kem_sizes() -> Vec<u64> {
    ensure_panic_hook_installed();
    vec![
        MLKEM768_PUBLIC_KEY_BYTES as u64,
        MLKEM768_SECRET_KEY_BYTES as u64,
        MLKEM768_CIPHERTEXT_BYTES as u64,
    ]
}

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

/// Generate a hybrid pairing keypair. NOTE (audit F10 follow-up): this is NO
/// LONGER a UniFFI export — it returns the private halves as plain `Vec<u8>`,
/// which would put secrets on the JVM heap for any Kotlin caller. The desktop
/// uses it as a same-process crate call (secrets never cross a boundary); the
/// Android companion MUST use `generate_pq_keypair_handle` (opaque handle).
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

// ── Hybrid KEM ──

/// Encapsulate to the peer's hybrid public keys. NOTE (audit F10 follow-up):
/// NOT a UniFFI export — `PqKemResponse` carries the raw `shared_secret`,
/// which must never sit on the JVM heap. Crate-internal only; the Android
/// companion uses `encapsulate_pq_secret_handle`.
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
    if peer_mlkem_pk.len() != MLKEM768_PUBLIC_KEY_BYTES {
        return Err(KyberError::InvalidKeyLength {
            expected: MLKEM768_PUBLIC_KEY_BYTES as u64,
            got: peer_mlkem_pk.len() as u64,
        });
    }
    let res = crypto::encapsulate_hybrid(&x25519_arr, &peer_mlkem_pk)?;
    Ok(PqKemResponse {
        ciphertext: res.ciphertext_bytes.clone(),
        shared_secret: res.combined_shared_secret.clone(),
    })
}

/// Decapsulate a hybrid KEM ciphertext. NOTE (audit F10 follow-up): NOT a
/// UniFFI export — it accepts raw private-key bytes from the caller and
/// returns the raw shared secret. Crate-internal only (desktop pairing); the
/// Android companion uses `decapsulate_pq_secret_handle`. The caller-owned sk
/// buffers are zeroized after use.
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
    if my_mlkem_sk.len() != MLKEM768_SECRET_KEY_BYTES {
        return Err(KyberError::InvalidKeyLength {
            expected: MLKEM768_SECRET_KEY_BYTES as u64,
            got: my_mlkem_sk.len() as u64,
        });
    }
    let result = crypto::decapsulate_hybrid(&ciphertext, &x25519_sk_arr, &my_mlkem_sk);
    let mut my_mlkem_sk = my_mlkem_sk;
    my_mlkem_sk.zeroize();
    result
}

// ── Session Key Derivation ──

/// Derive the session key from the raw KEM shared secret. NOTE (audit F10
/// follow-up): NOT a UniFFI export — raw secrets must not cross the boundary.
/// Crate-internal only; the Android companion uses `derive_session_key_handle`.
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

/// AUDIT P3-1 (MEDIUM): this was the LAST raw-key-across-the-boundary export
/// — the raw-param pairing exports were correctly removed (generate_pq_keypair,
/// encapsulate_pq_secret, derive_session_key are crate-internal), but
/// `session_key_create(Vec<u8>)` still accepted a full 32-byte key from the
/// JVM/C-ABI side, exposing it to the Android app process (which links the
/// same .so) with no trust-tier distinction from the desktop-internal caller.
/// The desktop legitimately needs it for keyring restore (F11) — but the
/// desktop calls it as a same-process CRATE function, so the export is
/// removed while the function stays `pub`: no UniFFI export accepts a raw key
/// anymore, and the generated Kotlin binding no longer exposes
/// `sessionKeyCreate`. The internal copy is zeroized by
/// [`session_handle::session_key_create`]'s Zeroizing wrapper.
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

/// Pin a session key handle so the LRU cap can never silently evict it (audit
/// finding #23). Returns false for an unknown handle. Pinned handles are still
/// destroyed explicitly via `session_key_destroy`.
#[uniffi::export]
pub fn session_key_pin(handle: u64) -> bool {
    ensure_panic_hook_installed();
    session_handle::session_key_pin(handle)
}

/// Unpin a session key handle, returning it to the pool of evictable handles.
#[uniffi::export]
pub fn session_key_unpin(handle: u64) {
    ensure_panic_hook_installed();
    session_handle::session_key_unpin(handle)
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

/// Verify a NIST ML-DSA-65 detached signature (audit F13). Exported so the
/// Android companion can authenticate LAN beacon payloads at DISCOVERY time:
/// the beacon embeds its own signing public key, and a self-consistent
/// signature proves the sender owns that key (the phone then adopts the key
/// during pairing). The signed region reconstructed by the caller MUST match
/// exactly what the sender signed (`pk:ip:timestamp:nonce`).
#[uniffi::export]
pub fn verify_mldsa_signature(payload: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
    ensure_panic_hook_installed();
    crate::crypto::verify_mldsa_signature(&payload, &signature, &public_key)
}

// ── Opaque Secret Handles (audit KYP-2026-02 #7) ──
// Raw pairing private halves and KEM shared secrets NEVER cross the FFI
// boundary. The Android app works exclusively with opaque handles; only public
// keys, SAS strings and ciphertexts are returned.

/// Generate a hybrid pairing keypair and return only an opaque handle. The
/// private halves stay in Rust and are zeroized when the handle is destroyed.
#[uniffi::export]
pub fn generate_pq_keypair_handle() -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    kem_handle::generate_pq_keypair_handle_impl()
}

/// The PUBLIC halves of a handle-held keypair (for QR / pairing payloads).
#[uniffi::export]
pub fn get_pq_keypair_public(handle: u64) -> Result<PqPairingPublic, KyberError> {
    ensure_panic_hook_installed();
    kem_handle::get_pq_keypair_public_impl(handle)
}

/// Destroy a keypair handle, zeroizing the private halves.
#[uniffi::export]
pub fn destroy_pq_keypair_handle(handle: u64) -> bool {
    ensure_panic_hook_installed();
    kem_handle::destroy_pq_keypair_handle_impl(handle)
}

/// Destroy EVERY keypair handle (zeroizing all private halves) — self-destruct
/// / unpair path.
#[uniffi::export]
pub fn destroy_all_pq_keypair_handles() {
    ensure_panic_hook_installed();
    kem_handle::destroy_all_pq_keypair_handles_impl();
}

/// Initialize a ratchet session using the keypair held behind `keypair_handle`
/// as the initial DH identity.
///
/// AUDIT F10: this export is GONE. The previous signature took
/// `master_shared_secret: Vec<u8>` — the caller had to receive and re-supply
/// the KEM shared secret, which put the secret on the JVM heap and contradicted
/// the documented "no secret bytes cross the FFI boundary" invariant of the
/// handle architecture. The ONLY public entry is
/// [`ratchet_init_session_from_kem_handle`] (handle → handle); the raw-param
/// implementation lives crate-internal in `kem_handle` where the secret is
/// looked up by handle and consumed without ever crossing the boundary.
///
/// Encapsulate to the peer's hybrid public keys. Returns an opaque handle to
/// the derived KEM shared secret (kept in Rust) plus the PUBLIC ciphertext that
/// is sent to the peer. The shared secret never crosses the FFI boundary.
#[uniffi::export]
pub fn encapsulate_pq_secret_handle(
    peer_x25519_pk: Vec<u8>,
    peer_mlkem_pk: Vec<u8>,
) -> Result<PqKemHandleResponse, KyberError> {
    ensure_panic_hook_installed();
    let (handle, ciphertext) =
        kem_handle::encapsulate_pq_secret_handle_impl(&peer_x25519_pk, &peer_mlkem_pk)?;
    Ok(PqKemHandleResponse { handle, ciphertext })
}

/// Decapsulate a hybrid KEM ciphertext with the private halves held behind
/// `keypair_handle`, returning an opaque handle to the recovered shared secret
/// (kept in Rust, zeroized on destroy).
#[uniffi::export]
pub fn decapsulate_pq_secret_handle(
    ciphertext: Vec<u8>,
    keypair_handle: u64,
) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    kem_handle::decapsulate_pq_secret_handle_impl(&ciphertext, keypair_handle)
}

/// Generate the pairing SAS from a handle-held KEM shared secret. Returns only
/// the (public) SAS string.
#[uniffi::export]
pub fn generate_sas_code_with_kem_handle(
    host_pk: Vec<u8>,
    client_mlkem_pk: Vec<u8>,
    kem_handle_id: u64,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    kem_handle::generate_sas_code_with_kem_handle_impl(&host_pk, &client_mlkem_pk, kem_handle_id)
}

/// Derive the session key from a handle-held KEM shared secret and return an
/// opaque SESSION KEY handle. The session key bytes never leave Rust.
#[uniffi::export]
pub fn derive_session_key_handle(kem_handle_id: u64) -> Result<u64, KyberError> {
    ensure_panic_hook_installed();
    kem_handle::derive_session_key_handle_impl(kem_handle_id)
}

/// Initialize a ratchet session entirely from opaque handles: the pairing
/// keypair handle (our DH identity) and the KEM shared-secret handle (master
/// secret). No secret bytes cross the FFI boundary.
#[uniffi::export]
pub fn ratchet_init_session_from_kem_handle(
    peer_identity: String,
    is_initiator: bool,
    keypair_handle: u64,
    kem_handle_id: u64,
    peer_x25519_pk: Vec<u8>,
    peer_mlkem_pk: Vec<u8>,
) -> Result<String, KyberError> {
    ensure_panic_hook_installed();
    let x25519 = if peer_x25519_pk.is_empty() {
        None
    } else {
        Some(peer_x25519_pk.as_slice())
    };
    let mlkem = if peer_mlkem_pk.is_empty() {
        None
    } else {
        Some(peer_mlkem_pk.as_slice())
    };
    kem_handle::ratchet_init_session_from_kem_handle_impl(
        &peer_identity,
        is_initiator,
        keypair_handle,
        kem_handle_id,
        x25519,
        mlkem,
    )?;
    Ok("Session initialized".to_string())
}

/// Destroy a KEM shared-secret handle (zeroizing the secret).
#[uniffi::export]
pub fn destroy_kem_handle(kem_handle_id: u64) -> bool {
    ensure_panic_hook_installed();
    kem_handle::destroy_kem_handle_impl(kem_handle_id)
}

/// Destroy every KEM shared-secret handle.
#[uniffi::export]
pub fn destroy_all_kem_handles() {
    ensure_panic_hook_installed();
    kem_handle::destroy_all_kem_handles_impl();
}

// ── Raw-Key API (audit finding #27) ──
// Use session_key_* with opaque handles instead.

/// AUDIT FINDING #27: this is the ONLY raw-key-across-the-boundary surface in
/// the library. It was originally misnamed `encrypt_payload_with_handle` —
/// which implied handle semantics while actually accepting the raw 32-byte
/// key. It is renamed to say exactly what it does, and the internal copy is
/// zeroized on drop so no unzeroized duplicate lingers on the stack/heap.
/// Every other key path goes through opaque handles.
#[uniffi::export]
pub fn encrypt_with_raw_key_32(
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
    // Zeroizing: the key copy is wiped when it drops, so an error path (or a
    // dropped EncryptedPayload) never leaves the key bytes in freed memory.
    let mut key_arr: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
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
pub fn decrypt_with_raw_key_32(
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
    // Zeroizing: the key copy is wiped when it drops (audit finding #27).
    let mut key_arr: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new([0u8; 32]);
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
