//! Opaque handle registries that keep secret material IN RUST (audit
//! KYP-2026-02 #7).
//!
//! The Android app previously received the pairing keypair's PRIVATE halves
//! and the KEM shared secret as plain Kotlin bytes: they lived in Compose
//! state, were re-encoded to hex (creating further copies), were never
//! zeroized, and survived on the JVM heap for the lifetime of the activity —
//! strictly weaker than the Rust core's `ZeroizeOnDrop` guarantee. These
//! exports retain the secret halves behind opaque `u64` handles (mirroring the
//! existing `session_key_handle` API), so only PUBLIC data — public keys, SAS
//! strings, ciphertexts — ever crosses the FFI boundary.

use crate::error::KyberError;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use zeroize::{Zeroize, Zeroizing};

/// Bounds on the opaque-handle registries. Handles are disposable — the
/// pairing keypair and the KEM shared secret are re-generated per pairing — so
/// a bounded cap + LRU-free "drop the oldest" keeps a buggy caller from
/// growing them without limit.
const MAX_KEYPAIR_HANDLES: usize = 64;
const MAX_KEM_HANDLES: usize = 256;

/// A secret-bearing pairing keypair retained in Rust. Zeroized on drop.
/// Stores the internal [`crate::SecretKeypair`] (audit F14) whose private
/// halves are `Zeroizing` buffers, so even a CLONE handed to a caller is wiped
/// when it drops — a plain `PqKeyPair` clone would leave raw private bytes in
/// freed heap.
pub struct KeypairSecret {
    pair: crate::SecretKeypair,
}

impl Drop for KeypairSecret {
    fn drop(&mut self) {
        self.pair.zeroize();
    }
}

static KEYPAIR_HANDLE_REGISTRY: LazyLock<Mutex<HashMap<u64, KeypairSecret>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_KEYPAIR_HANDLE: AtomicU64 = AtomicU64::new(1);

static KEM_SECRET_REGISTRY: LazyLock<Mutex<HashMap<u64, Zeroizing<Vec<u8>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_KEM_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Generate a hybrid keypair and return only an opaque handle. The private
/// halves stay in Rust and are zeroized when the handle is destroyed (or the
/// registry is dropped).
pub fn generate_pq_keypair_handle_impl() -> Result<u64, KyberError> {
    let pair = crate::crypto::generate_hybrid_keypair();
    let keypair = crate::SecretKeypair {
        x25519_pk: pair.x25519_pk.to_vec(),
        x25519_sk: zeroize::Zeroizing::new(pair.x25519_sk.to_vec()),
        mlkem_pk: pair.mlkem_pk.clone(),
        mlkem_sk: zeroize::Zeroizing::new(pair.mlkem_sk.to_vec()),
    };
    let mut reg = KEYPAIR_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if reg.len() >= MAX_KEYPAIR_HANDLES {
        // Drop the oldest handle (its private halves are zeroized on drop).
        if let Some(oldest) = reg.keys().next().copied() {
            reg.remove(&oldest);
        }
    }
    let handle = NEXT_KEYPAIR_HANDLE.fetch_add(1, Ordering::AcqRel);
    reg.insert(handle, KeypairSecret { pair: keypair });
    Ok(handle)
}

/// The PUBLIC halves of a handle-held keypair (for QR/pairing payloads). Never
/// returns the private halves.
pub fn get_pq_keypair_public_impl(handle: u64) -> Result<crate::PqPairingPublic, KyberError> {
    let reg = KEYPAIR_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let secret = reg
        .get(&handle)
        .ok_or_else(|| KyberError::CryptoError(format!("Invalid keypair handle {handle}")))?;
    Ok(secret.pair.public())
}

/// Destroy a keypair handle, zeroizing the private halves. Returns whether the
/// handle existed.
pub fn destroy_pq_keypair_handle_impl(handle: u64) -> bool {
    let mut reg = KEYPAIR_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    reg.remove(&handle).is_some()
}

/// Destroy EVERY keypair handle (zeroizing all private halves). Wired into the
/// self-destruct / unpair paths (audit KYP-2026-02 #15).
pub fn destroy_all_pq_keypair_handles_impl() {
    KEYPAIR_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

/// Clone the secret-bearing keypair out of the registry through ZEROIZING
/// buffers (audit F14): the returned private halves are `Zeroizing<Vec<u8>>`,
/// so every caller path — including error returns and drops — wipes them from
/// the heap. Never hands out a plain `PqKeyPair` clone (whose private Vecs
/// would survive in freed heap after drop).
fn keypair_secret(handle: u64) -> Result<crate::SecretKeypair, KyberError> {
    let reg = KEYPAIR_HANDLE_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    reg.get(&handle)
        .map(|s| s.pair.clone())
        .ok_or_else(|| KyberError::CryptoError(format!("Invalid keypair handle {handle}")))
}

/// Initialize a ratchet session using the keypair held behind `keypair_handle`
/// as the initial DH identity (the production entry point — audit finding #1).
/// The private halves never leave Rust.
pub fn ratchet_init_session_with_keypair_handle_impl(
    peer_identity: &str,
    master_shared_secret: &[u8],
    is_initiator: bool,
    keypair_handle: u64,
    peer_x25519_pk: Option<&[u8]>,
    peer_mlkem_pk: Option<&[u8]>,
) -> Result<(), KyberError> {
    let pair = keypair_secret(keypair_handle)?;
    // The impl copies the secret halves into [u8;32] and a ZeroizeOnDrop
    // HybridKeyPair. AUDIT #2 (follow-up): the private-half clones are passed
    // through as `Zeroizing<Vec<u8>>` (the `SecretKeypair` fields already are),
    // so the transient buffers are wiped on drop — even on the error path. The
    // former `(*pair.x25519_sk).clone()` deref'd the Zeroizing wrapper down to a
    // PLAIN `Vec<u8>`, which contradicted the F14 guarantee and left raw X25519/
    // ML-KEM secret bytes in freed heap.
    crate::ratchet_ffi::ratchet_init_session_with_keypair_impl(
        peer_identity,
        master_shared_secret,
        is_initiator,
        Some((
            pair.x25519_pk.clone(),
            pair.x25519_sk.clone(),
            pair.mlkem_pk.clone(),
            pair.mlkem_sk.clone(),
        )),
        peer_x25519_pk,
        peer_mlkem_pk,
    )
}

/// Encapsulate to the peer's hybrid public keys, returning an opaque handle to
/// the derived KEM shared secret (kept in Rust, zeroized on destroy) plus the
/// PUBLIC ciphertext that is sent to the peer.
pub fn encapsulate_pq_secret_handle_impl(
    peer_x25519_pk: &[u8],
    peer_mlkem_pk: &[u8],
) -> Result<(u64, Vec<u8>), KyberError> {
    if peer_x25519_pk.len() != 32 {
        return Err(KyberError::InvalidKeyLength {
            expected: 32,
            got: peer_x25519_pk.len() as u64,
        });
    }
    if peer_mlkem_pk.len() != crate::crypto_api::MLKEM768_PUBLIC_KEY_BYTES {
        return Err(KyberError::InvalidKeyLength {
            expected: crate::crypto_api::MLKEM768_PUBLIC_KEY_BYTES as u64,
            got: peer_mlkem_pk.len() as u64,
        });
    }
    let mut x25519_arr = [0u8; 32];
    x25519_arr.copy_from_slice(peer_x25519_pk);
    let res = crate::crypto::encapsulate_hybrid(&x25519_arr, peer_mlkem_pk)?;
    let mut reg = KEM_SECRET_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if reg.len() >= MAX_KEM_HANDLES {
        if let Some(oldest) = reg.keys().next().copied() {
            reg.remove(&oldest); // drop zeroizes the shared secret
        }
    }
    let handle = NEXT_KEM_HANDLE.fetch_add(1, Ordering::AcqRel);
    reg.insert(handle, Zeroizing::new(res.combined_shared_secret.clone()));
    Ok((handle, res.ciphertext_bytes.clone()))
}

/// Decapsulate a hybrid KEM ciphertext with the private halves held behind
/// `keypair_handle`, returning an opaque handle to the recovered shared secret
/// (kept in Rust, zeroized on destroy). Mirrors [`encapsulate_pq_secret_handle`]
/// so the same secret on the peer side (which decapsulates) is also retained
/// behind a handle.
pub fn decapsulate_pq_secret_handle_impl(
    ciphertext: &[u8],
    keypair_handle: u64,
) -> Result<u64, KyberError> {
    let pair = keypair_secret(keypair_handle)?;
    let mut x25519_arr = [0u8; 32];
    x25519_arr.copy_from_slice(&pair.x25519_sk);
    // `mlkem_sk` is a Zeroizing<Vec<u8>> (audit F14): passing `&pair.mlkem_sk`
    // derefs to `&[u8]` and the buffer is wiped on drop.
    let secret = crate::crypto::decapsulate_hybrid(ciphertext, &x25519_arr, &pair.mlkem_sk)?;
    let mut reg = KEM_SECRET_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if reg.len() >= MAX_KEM_HANDLES {
        if let Some(oldest) = reg.keys().next().copied() {
            reg.remove(&oldest); // drop zeroizes the shared secret
        }
    }
    let handle = NEXT_KEM_HANDLE.fetch_add(1, Ordering::AcqRel);
    reg.insert(handle, Zeroizing::new(secret));
    Ok(handle)
}

/// Generate the pairing SAS from a handle-held KEM shared secret. Returns only
/// the (public) SAS string.
pub fn generate_sas_code_with_kem_handle_impl(
    host_pk: &[u8],
    client_mlkem_pk: &[u8],
    kem_handle: u64,
) -> Result<String, KyberError> {
    let secret = kem_secret(kem_handle)?;
    crate::crypto::sas::generate_sas_code(host_pk, client_mlkem_pk, &secret)
}

/// Derive the session key from a handle-held KEM shared secret and return an
/// opaque SESSION KEY handle (the session key bytes never leave Rust).
pub fn derive_session_key_handle_impl(kem_handle: u64) -> Result<u64, KyberError> {
    let secret = kem_secret(kem_handle)?;
    let derived = crate::crypto::derive_session_key(
        &secret,
        crate::crypto::SESSION_KEY_DERIVATION_SALT,
        b"kyberpipe-hybrid-session",
    )?;
    crate::session_handle::session_key_create(derived.to_vec())
}

/// Initialize a ratchet session entirely from opaque handles: the pairing
/// keypair handle (our DH identity) and the KEM shared secret handle (master
/// secret). No secret bytes cross the FFI boundary.
pub fn ratchet_init_session_from_kem_handle_impl(
    peer_identity: &str,
    is_initiator: bool,
    keypair_handle: u64,
    kem_handle: u64,
    peer_x25519_pk: Option<&[u8]>,
    peer_mlkem_pk: Option<&[u8]>,
) -> Result<(), KyberError> {
    let secret = kem_secret(kem_handle)?;
    ratchet_init_session_with_keypair_handle_impl(
        peer_identity,
        &secret,
        is_initiator,
        keypair_handle,
        peer_x25519_pk,
        peer_mlkem_pk,
    )
}

fn kem_secret(kem_handle: u64) -> Result<Zeroizing<Vec<u8>>, KyberError> {
    let reg = KEM_SECRET_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    reg.get(&kem_handle)
        .cloned()
        .ok_or_else(|| KyberError::CryptoError(format!("Invalid KEM secret handle {kem_handle}")))
}

/// Destroy a KEM shared-secret handle (zeroizing the secret). Returns whether
/// the handle existed.
pub fn destroy_kem_handle_impl(kem_handle: u64) -> bool {
    let mut reg = KEM_SECRET_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    reg.remove(&kem_handle).is_some()
}

/// Destroy every KEM shared-secret handle.
pub fn destroy_all_kem_handles_impl() {
    KEM_SECRET_REGISTRY
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_handle_never_exposes_private_halves() {
        let handle = generate_pq_keypair_handle_impl().expect("handle");
        let public = get_pq_keypair_public_impl(handle).expect("public");
        // Only public keys are exposed via the handle API.
        assert_eq!(
            public.mlkem_pk_hex.len(),
            crate::crypto_api::MLKEM768_PUBLIC_KEY_BYTES * 2
        );
        assert_eq!(public.x25519_pk_hex.len(), 64);
        assert!(destroy_pq_keypair_handle_impl(handle));
        assert!(!destroy_pq_keypair_handle_impl(handle));
        assert!(get_pq_keypair_public_impl(handle).is_err());
    }

    #[test]
    fn kem_handle_roundtrip_derives_consistent_sas_and_key() {
        // Fully handle-based flow: the receiver's keypair lives behind a
        // handle; the sender encapsulates to its PUBLIC keys; the receiver
        // decapsulates into a handle.
        let bob_handle = generate_pq_keypair_handle_impl().expect("bob handle");
        let bob_pub = get_pq_keypair_public_impl(bob_handle).expect("bob public");
        let bob_x25519 = hex::decode(&bob_pub.x25519_pk_hex).unwrap();
        let bob_mlkem = hex::decode(&bob_pub.mlkem_pk_hex).unwrap();
        // A separate client keypair (public halves only needed for the SAS).
        let client_handle = generate_pq_keypair_handle_impl().expect("client handle");
        let client_pub = get_pq_keypair_public_impl(client_handle).expect("client public");
        let client_mlkem = hex::decode(&client_pub.mlkem_pk_hex).unwrap();

        let (kem_handle, ct) =
            encapsulate_pq_secret_handle_impl(&bob_x25519, &bob_mlkem).expect("encapsulate");
        let bob_dec_handle =
            decapsulate_pq_secret_handle_impl(&ct, bob_handle).expect("decapsulate to handle");
        let secret = kem_secret(kem_handle).expect("kem secret");
        let bob_secret = kem_secret(bob_dec_handle).expect("bob kem secret");
        assert_eq!(
            *secret, *bob_secret,
            "both sides must recover the identical shared secret"
        );

        // The SAS computed from the handle matches the SAS computed from the
        // raw bytes (canonical consistency across the FFI boundary).
        let sas_handle =
            generate_sas_code_with_kem_handle_impl(&bob_mlkem, &client_mlkem, kem_handle)
                .expect("sas via handle");
        let sas_raw = crate::crypto::sas::generate_sas_code(&bob_mlkem, &client_mlkem, &secret)
            .expect("sas raw");
        assert_eq!(sas_handle, sas_raw);

        // The session key derived via the handle must equal the classic
        // derivation (same bytes). A second handle for the IDENTICAL key bytes
        // is rejected by session_key_create's duplicate-key guard, proving the
        // handle-derived key is byte-identical to the classic derivation.
        let sk_handle = derive_session_key_handle_impl(kem_handle).expect("session key handle");
        let sk_raw = crate::crypto::derive_session_key(
            &secret,
            crate::crypto::SESSION_KEY_DERIVATION_SALT,
            b"kyberpipe-hybrid-session",
        )
        .expect("derive raw");
        let dup = crate::session_handle::session_key_create(sk_raw.to_vec());
        assert!(
            dup.is_err(),
            "duplicate key bytes must be rejected — proving handle-derived == classic-derived"
        );
        // Cleanup.
        crate::session_handle::session_key_destroy(sk_handle);
        assert!(destroy_kem_handle_impl(kem_handle));
        assert!(destroy_kem_handle_impl(bob_dec_handle));
        assert!(destroy_pq_keypair_handle_impl(bob_handle));
        assert!(destroy_pq_keypair_handle_impl(client_handle));
    }

    #[test]
    fn ratchet_init_from_handles_works() {
        let alice_handle = generate_pq_keypair_handle_impl().expect("alice handle");
        let bob_handle = generate_pq_keypair_handle_impl().expect("bob handle");
        let alice_pub = get_pq_keypair_public_impl(alice_handle).expect("alice pub");
        let bob_pub = get_pq_keypair_public_impl(bob_handle).expect("bob pub");

        // Alice encapsulates to Bob's public keys; Bob DECAPSULATES the same
        // ciphertext with his handle-held keypair — both sides recover the
        // IDENTICAL shared secret (the real pairing flow).
        let (kem_ab, ct_ab) = encapsulate_pq_secret_handle_impl(
            &hex::decode(&bob_pub.x25519_pk_hex).unwrap(),
            &hex::decode(&bob_pub.mlkem_pk_hex).unwrap(),
        )
        .expect("ab");
        let kem_ba = decapsulate_pq_secret_handle_impl(&ct_ab, bob_handle).expect("ba decap");

        let peer_alice = crate::ratchet_ffi::ratchet_peer_ids_impl();
        for p in peer_alice {
            crate::ratchet_ffi::ratchet_remove_session_impl(&p);
        }
        let alice_id = "alice-handle-test";
        let bob_id = "bob-handle-test";
        crate::ratchet_ffi::ratchet_remove_session_impl(alice_id);
        crate::ratchet_ffi::ratchet_remove_session_impl(bob_id);
        ratchet_init_session_from_kem_handle_impl(
            alice_id,
            true,
            alice_handle,
            kem_ab,
            Some(&hex::decode(&bob_pub.x25519_pk_hex).unwrap()),
            Some(&hex::decode(&bob_pub.mlkem_pk_hex).unwrap()),
        )
        .expect("alice init");
        ratchet_init_session_from_kem_handle_impl(
            bob_id,
            false,
            bob_handle,
            kem_ba,
            Some(&hex::decode(&alice_pub.x25519_pk_hex).unwrap()),
            Some(&hex::decode(&alice_pub.mlkem_pk_hex).unwrap()),
        )
        .expect("bob init");

        let msg = crate::ratchet_ffi::ratchet_encrypt_message_impl(alice_id, b"hello-handle")
            .expect("encrypt");
        let pt =
            crate::ratchet_ffi::ratchet_decrypt_message_impl(bob_id, &msg.nonce, &msg.ciphertext)
                .expect("decrypt");
        assert_eq!(pt, b"hello-handle");

        crate::ratchet_ffi::ratchet_remove_session_impl(alice_id);
        crate::ratchet_ffi::ratchet_remove_session_impl(bob_id);
        assert!(destroy_pq_keypair_handle_impl(alice_handle));
        assert!(destroy_pq_keypair_handle_impl(bob_handle));
        assert!(destroy_kem_handle_impl(kem_ab));
        assert!(destroy_kem_handle_impl(kem_ba));
    }
}
